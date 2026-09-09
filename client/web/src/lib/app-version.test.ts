import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getServerVersion, reloadWithLatestClient, versionsMatch } from '$lib/app-version'
import { Request } from '$lib/request'

vi.mock('$lib/request', () => ({
    Request: vi.fn(),
}))

const requestMock = vi.mocked(Request)

beforeEach(() => {
    requestMock.mockReset()
})

afterEach(() => {
    vi.unstubAllGlobals()
})

describe('versionsMatch', () => {
    it('matches identical versions', () => {
        expect(versionsMatch('2.4.1', '2.4.1')).toBe(true)
    })

    it('rejects different versions', () => {
        expect(versionsMatch('2.4.0', '2.4.1')).toBe(false)
    })
})

describe('getServerVersion', () => {
    it('reads the version from the server info document', async () => {
        requestMock.mockResolvedValue({
            data: {
                product: 'revaulter',
                version: '2.4.1',
            },
        })

        await expect(getServerVersion()).resolves.toBe('2.4.1')
        expect(requestMock).toHaveBeenCalledWith('/info')
    })

    it('rejects a response without a version', async () => {
        requestMock.mockResolvedValue({
            data: {
                product: 'revaulter',
            },
        })

        await expect(getServerVersion()).rejects.toThrow('Server info did not contain a valid version')
    })
})

describe('reloadWithLatestClient', () => {
    it('activates an updated service worker before reloading', async () => {
        let workerState: ServiceWorkerState = 'installed'
        const worker = new EventTarget() as EventTarget & {
            postMessage: ReturnType<typeof vi.fn>
            readonly state: ServiceWorkerState
        }
        Object.defineProperty(worker, 'state', {
            get: () => workerState,
        })
        worker.postMessage = vi.fn(() => {
            workerState = 'activated'
            worker.dispatchEvent(new Event('statechange'))
        })

        const update = vi.fn().mockResolvedValue(undefined)
        const registration = new EventTarget() as EventTarget & {
            installing: ServiceWorker
            update: ReturnType<typeof vi.fn>
            waiting: ServiceWorker | null
        }
        registration.installing = worker as unknown as ServiceWorker
        registration.waiting = null
        registration.update = update

        const reload = vi.fn()
        vi.stubGlobal('navigator', {
            serviceWorker: {
                getRegistration: vi.fn().mockResolvedValue(registration),
            },
        })
        vi.stubGlobal('window', {
            location: { reload },
        })

        await reloadWithLatestClient()

        expect(update).toHaveBeenCalledOnce()
        expect(worker.postMessage).toHaveBeenCalledWith({ type: 'SKIP_WAITING' })
        expect(reload).toHaveBeenCalledOnce()
    })

    it('reloads normally when there is no service worker registration', async () => {
        const reload = vi.fn()
        vi.stubGlobal('navigator', {
            serviceWorker: {
                getRegistration: vi.fn().mockResolvedValue(undefined),
            },
        })
        vi.stubGlobal('window', {
            location: { reload },
        })

        await reloadWithLatestClient()

        expect(reload).toHaveBeenCalledOnce()
    })

    it('reloads normally when the service worker update fails', async () => {
        const reload = vi.fn()
        vi.stubGlobal('navigator', {
            serviceWorker: {
                getRegistration: vi.fn().mockRejectedValue(new Error('update failed')),
            },
        })
        vi.stubGlobal('window', {
            location: { reload },
        })

        await reloadWithLatestClient()

        expect(reload).toHaveBeenCalledOnce()
    })
})
