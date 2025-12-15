import './style.css'

import { mount } from 'svelte'
import App from './App.svelte'

// Load the app
mount(App, {
    target: document.body,
})

// Register the service worker
// Somehow, we need to ts-ignore the next line or compilation will fail
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
if (PRODUCTION && navigator.serviceWorker !== undefined) {
    window.addEventListener('load', () => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        navigator.serviceWorker.register('/sw.js').catch((err: unknown) => {
            // eslint-disable-next-line no-console
            console.warn('SW registration failed: ', err)
        })
    })
}
