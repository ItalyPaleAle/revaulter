import path from 'node:path'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'
import { analyzer } from 'vite-bundle-analyzer'
import { VitePWA } from 'vite-plugin-pwa'
import sri from 'vite-plugin-sri-gen'

export default defineConfig(({ mode }) => {
    console.log('Building for mode', mode)

    // Additional plugins, which may not always be used
    const additionalPlugins = []

    const isProduction = mode === 'production'

    // In "analyze" mode, add the analyzer plugin
    if (mode == 'analyze') {
        additionalPlugins.push(analyzer())
    }

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
                    icons: [
                        {
                            src: 'favicon.svg',
                            sizes: 'any',
                            type: 'image/svg+xml',
                        },
                    ],
                },
                devOptions: {
                    enabled: false,
                },
            }),
            sri(),
            ...additionalPlugins,
        ],
        resolve: {
            alias: {
                '$lib': path.resolve(__dirname, './src/lib'),
                '$components': path.resolve(__dirname, './src/components'),
            },
        },
        define: {},
        test: {
            exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
        },
        build: {
            outDir: 'dist',
            emptyOutDir: true,
            sourcemap: !isProduction,
            rollupOptions: {
                output: {
                    entryFileNames: '[name].[hash].js',
                    chunkFileNames: '[name].[hash].js',
                    assetFileNames: '[name].[hash].[ext]',
                    manualChunks: {
                        lib: ['svelte', 'date-fns'],
                        crypto: ['hash-wasm', 'arraybuffer-encoding'],
                    },
                },
            },
        },
        server: {
            port: 3000,
            proxy: {
                // Proxy API routes for development
                '/v2': {
                    target: 'http://localhost:8080',
                    changeOrigin: true,
                },
            },
        },
    }
})
