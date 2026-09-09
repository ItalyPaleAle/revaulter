import { Request } from '$lib/request'

const serviceWorkerActivationTimeout = 10_000

type ServerInfo = {
    product?: unknown
    version?: unknown
}

export const appVersion = __APP_VERSION__

export function versionsMatch(clientVersion: string, serverVersion: string): boolean {
    return clientVersion === serverVersion
}

export async function getServerVersion(): Promise<string> {
    const response = await Request<ServerInfo>('/info')
    const info = response.data

    if (info.product !== 'revaulter') {
        throw new Error('Server info did not identify Revaulter')
    }
    if (typeof info.version !== 'string' || info.version.trim() === '') {
        throw new Error('Server info did not contain a valid version')
    }

    return info.version
}

async function waitForServiceWorkerActivation(worker: ServiceWorker): Promise<void> {
    if (worker.state === 'activated' || worker.state === 'redundant') {
        return
    }

    await new Promise<void>((resolve) => {
        let finished = false
        let timeout: ReturnType<typeof setTimeout>

        const finish = () => {
            if (finished) {
                return
            }
            finished = true
            clearTimeout(timeout)
            worker.removeEventListener('statechange', onStateChange)
            resolve()
        }
        const onStateChange = () => {
            if (worker.state === 'installed') {
                worker.postMessage({ type: 'SKIP_WAITING' })
            }
            if (worker.state === 'activated' || worker.state === 'redundant') {
                finish()
            }
        }

        worker.addEventListener('statechange', onStateChange)
        timeout = setTimeout(finish, serviceWorkerActivationTimeout)
        onStateChange()
    })
}

async function activateLatestServiceWorker(registration: ServiceWorkerRegistration): Promise<void> {
    let updatedWorker = registration.installing ?? registration.waiting
    const onUpdateFound = () => {
        updatedWorker = registration.installing ?? registration.waiting
    }

    registration.addEventListener('updatefound', onUpdateFound)
    try {
        await registration.update()
    } finally {
        registration.removeEventListener('updatefound', onUpdateFound)
    }

    updatedWorker ??= registration.installing ?? registration.waiting
    if (updatedWorker) {
        await waitForServiceWorkerActivation(updatedWorker)
    }
}

export async function reloadWithLatestClient(): Promise<void> {
    try {
        if ('serviceWorker' in navigator) {
            const registration = await navigator.serviceWorker.getRegistration()
            if (registration) {
                await activateLatestServiceWorker(registration)
            }
        }
    } catch {
        // A normal reload leaves the version gate in place when the updated worker could not be activated
    }

    window.location.reload()
}
