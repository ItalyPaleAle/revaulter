import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'
import sri from 'vite-plugin-sri-gen'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => {
    const isProduction = mode === 'production'

    return {
        plugins: [
            svelte(),
            tailwindcss(),
            VitePWA({
                registerType: 'autoUpdate',
                workbox: {
                    // Include the compiled files and assets
                    globPatterns: ['**/*.{js,css,html,svg,png,ico,woff,woff2}'],
                    globIgnores: ['**/*.map', '**/manifest*.json', '**/*.LICENSE.txt'],
                    // Inline the Workbox runtime into the sw.js file
                    inlineWorkboxRuntime: true,
                    // Disable navigation fallback so SW only serves exact precached URLs
                    navigateFallback: null,
                    // No runtime caching - only serve precached assets
                    runtimeCaching: [],
                    // Clean up old caches from previous versions
                    cleanupOutdatedCaches: true,
                },
                manifest: {
                    name: 'Revaulter',
                    short_name: 'Revaulter',
                    theme_color: '#1e293b',
                    background_color: '#f8fafc',
                    display: 'standalone',
                    icons: [],
                },
                devOptions: {
                    enabled: false,
                },
            }),
            sri(),
        ],
        define: {},
        build: {
            outDir: 'dist',
            emptyOutDir: true,
            sourcemap: !isProduction,
            rollupOptions: {
                output: {
                    entryFileNames: '[name].[hash].js',
                    chunkFileNames: '[name].[hash].js',
                    assetFileNames: '[name].[hash].[ext]',
                },
            },
        },
        server: {
            port: 3000,
        },
    }
})
