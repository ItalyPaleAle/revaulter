import { spawn } from 'node:child_process'
import { appendFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const args = new Map(
    process.argv.slice(2).map((entry) => {
        const [key, value] = entry.split('=', 2)
        return [key, value]
    })
)
const portArg = args.get('--port')
const port = Number.parseInt(portArg ?? '41741', 10)

if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`Invalid port: ${portArg ?? ''}`)
}

const currentDir = dirname(fileURLToPath(import.meta.url))
const clientDir = resolve(currentDir, '..')
const repoRoot = resolve(clientDir, '..', '..')
const binaryPath = join(repoRoot, '.bin', 'revaulter-e2e')

if (!existsSync(binaryPath)) {
    throw new Error(`Missing e2e binary at ${binaryPath}. Run "pnpm run e2e:build-server" first.`)
}

const tempDir = mkdtempSync(join(tmpdir(), 'revaulter-playwright-'))
const configPath = join(tempDir, 'config.yaml')
const databasePath = join(tempDir, 'revaulter-e2e.db')
const logPath = join(tempDir, 'server.log')
const databaseDSN = process.env.E2E_DATABASE_DSN || databasePath
const secretKey = Buffer.alloc(32, 7).toString('base64')
const e2eToken = process.env.REVAULTER_E2E_TOKEN || 'playwright-e2e-token-fixed'

writeFileSync(
    configPath,
    [
        'webhookUrl: "http://127.0.0.1:9/webhook"',
        `baseUrl: "http://localhost:${port}"`,
        'bind: "127.0.0.1"',
        `port: ${port}`,
        `databaseDSN: "${databaseDSN}"`,
        `secretKey: "${secretKey}"`,
        'webauthnRpId: "localhost"',
        `webauthnOrigins: ["http://localhost:${port}"]`,
        'logLevel: "error"',
        'omitHealthCheckLogs: true',
        '',
    ].join('\n')
)

const serverProcess = spawn(binaryPath, {
    cwd: repoRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
        ...process.env,
        REVAULTER_CONFIG: configPath,
        REVAULTER_E2E_TOKEN: e2eToken,
        OTEL_LOGS_EXPORTER: 'none',
        OTEL_METRICS_EXPORTER: 'none',
        OTEL_TRACES_EXPORTER: 'none',
    },
})

for (const stream of [serverProcess.stdout, serverProcess.stderr]) {
    stream?.on('data', (chunk) => {
        const text = chunk.toString()
        appendFileSync(logPath, text)
        process.stderr.write(text)
    })
}

let cleanedUp = false

function cleanup() {
    if (cleanedUp) {
        return
    }
    cleanedUp = true
    rmSync(tempDir, { recursive: true, force: true })
}

serverProcess.on('exit', (code, signal) => {
    if ((code ?? 0) !== 0 || signal) {
        process.stderr.write(`\nserver exited unexpectedly. Log: ${logPath}\n`)
    }

    cleanup()
    if (signal) {
        process.kill(process.pid, signal)
        return
    }
    process.exit(code ?? 0)
})

for (const eventName of ['SIGINT', 'SIGTERM']) {
    process.on(eventName, () => {
        serverProcess.kill(eventName)
    })
}

process.on('exit', cleanup)
