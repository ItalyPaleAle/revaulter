import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const defaultServerURL = process.env.PLAYWRIGHT_TEST_BASE_URL || 'http://localhost:41741'
const currentDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(currentDir, '..', '..', '..')

function goEnv() {
    return {
        ...process.env,
        GOEXPERIMENT: process.env.GOEXPERIMENT || 'jsonv2',
    }
}

function spawnCaptured(command, args, options = {}) {
    const child = spawn(command, args, {
        cwd: options.cwd || repoRoot,
        env: options.env || process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
    })

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (chunk) => {
        stdout += chunk.toString()
    })
    child.stderr.on('data', (chunk) => {
        stderr += chunk.toString()
    })

    const done = new Promise((resolve, reject) => {
        child.on('error', reject)
        child.on('close', (code, signal) => {
            if (code === 0) {
                resolve({ stdout, stderr })
                return
            }

            reject(new Error(`${command} exited with ${signal || code}\n${stderr || stdout}`))
        })
    })

    return {
        child,
        done,
        output() {
            return { stdout, stderr }
        },
    }
}

async function waitForOutput(getOutput, predicate, errorMessage, timeoutMs = 30_000) {
    const started = Date.now()

    while (Date.now() - started < timeoutMs) {
        const output = getOutput()
        if (predicate(output)) {
            return output
        }

        await new Promise((resolve) => {
            setTimeout(resolve, 50)
        })
    }

    const output = getOutput()
    throw new Error(`${errorMessage}\nSTDOUT:\n${output.stdout}\nSTDERR:\n${output.stderr}`)
}

export async function runCLITrust({ requestKey, trustStorePath, server = defaultServerURL }) {
    const trustRun = spawnCaptured(
        'go',
        ['run', './cmd/cli', 'trust', '--server', server, '--request-key', requestKey, '--trust-store', trustStorePath, '--yes'],
        { env: goEnv() }
    )
    return trustRun.done
}

export async function startCLISshAgent({ keyLabel, requestKey, socketPath, trustStorePath, server = defaultServerURL }) {
    const agentRun = spawnCaptured(
        'go',
        [
            'run',
            './cmd/cli',
            'ssh-agent',
            '--server',
            server,
            '--request-key',
            requestKey,
            '--key-label',
            keyLabel,
            '--socket',
            socketPath,
            '--trust-store',
            trustStorePath,
        ],
        { env: goEnv() }
    )

    await waitForOutput(
        agentRun.output,
        (output) => {
            return output.stderr.includes(`export SSH_AUTH_SOCK='${socketPath}'`) || output.stderr.includes(`export SSH_AUTH_SOCK=${socketPath}`)
        },
        'Timed out waiting for revaulter ssh-agent to start'
    )

    return agentRun
}

export async function listSshAgentKeys(socketPath) {
    const listRun = spawnCaptured('ssh-add', ['-L'], {
        env: {
            ...process.env,
            SSH_AUTH_SOCK: socketPath,
        },
    })

    const result = await listRun.done
    return result.stdout.trim().split('\n').filter(Boolean)
}

export async function startLocalSSHServer({ authorizedKey, message = 'hello from revaulter ssh e2e\n' }) {
    const tempRoot = mkdtempSync(join(tmpdir(), 'revaulter-e2e-ssh-server-'))
    const authorizedKeyPath = join(tempRoot, 'authorized_key')
    writeFileSync(authorizedKeyPath, `${authorizedKey.trim()}\n`)

    const serverRun = spawnCaptured(
        'go',
        ['run', './tools/e2e-ssh-server', '--authorized-key-file', authorizedKeyPath, '--message', message],
        { env: goEnv() }
    )

    const output = await waitForOutput(
        serverRun.output,
        (currentOutput) => {
            return /^READY /m.test(currentOutput.stdout)
        },
        'Timed out waiting for local SSH server to start'
    )

    const match = output.stdout.match(/^READY (.+)$/m)
    if (!match) {
        throw new Error(`Could not parse SSH server address\n${output.stdout}`)
    }

    return {
        ...serverRun,
        address: match[1].trim(),
        cleanup() {
            rmSync(tempRoot, { recursive: true, force: true })
        },
    }
}

export function startSSHCommand({ address, socketPath, user = 'playwright' }) {
    const addressParts = address.split(':')
    const port = addressParts.pop()
    const host = addressParts.join(':')

    if (!port || !host) {
        throw new Error(`Invalid SSH server address: ${address}`)
    }

    return spawnCaptured(
        'ssh',
        [
            '-T',
            '-o',
            `IdentityAgent=${socketPath}`,
            '-o',
            'IdentityFile=/dev/null',
            '-o',
            'IdentitiesOnly=no',
            '-o',
            'PubkeyAuthentication=yes',
            '-o',
            'PreferredAuthentications=publickey',
            '-o',
            'BatchMode=yes',
            '-o',
            'StrictHostKeyChecking=no',
            '-o',
            'UserKnownHostsFile=/dev/null',
            '-p',
            port,
            `${user}@${host}`,
            'revaulter-ssh-e2e',
        ],
        {
            env: {
                ...process.env,
                SSH_AUTH_SOCK: socketPath,
            },
        }
    )
}

export async function stopProcess(run) {
    if (!run) {
        return
    }

    const exited = run.done.catch(() => undefined)
    if (run.child.exitCode === null && !run.child.killed) {
        run.child.kill('SIGTERM')
    }
    await exited
}
