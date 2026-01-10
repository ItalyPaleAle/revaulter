import './style.css'

import { mount } from 'svelte'
import App from './App.svelte'

// Load the app
mount(App, {
    target: document.body,
})
