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
    const libChunkPattern = /[\\/]node_modules[\\/](svelte|date-fns)[\\/]/
    const cryptoChunkPattern = /[\\/]node_modules[\\/](@noble\/(hashes|post-quantum)|arraybuffer-encoding)[\\/]/

    const isProduction = mode === 'production'
    const isE2E = mode === 'e2e'

    // In "analyze" mode, add the analyzer plugin
    if (mode == 'analyze') {
        additionalPlugins.push(analyzer())
    }

    // Argon2id cost baked into the bundle at build time
    const argon2idCost = isE2E
        ? // E2E mode uses a trivially small cost to optimize test runs
          // This value MUST NOT leak into a production build
          { m: 8, t: 1, p: 1 }
        : // Production and development mode
          // These settings roughly exceed the current OWASP Argon2id guidance as of April 2026 (m=128 MiB, t=4, p=1) and aim for well over 500 ms of work on modern laptops while still being tolerable in-browser
          { m: 128 << 10, t: 4, p: 1 }

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
                            src: 'favicon-dark.svg',
                            sizes: 'any',
                            type: 'image/svg+xml',
                        },
                        {
                            src: 'apple-touch-icon.svg',
                            sizes: '180x180',
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
                '$assets': path.resolve(__dirname, './src/assets'),
            },
        },
        define: {
            __ARGON2ID_COST__: JSON.stringify(argon2idCost),
        },
        test: {
            exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
        },
        build: {
            outDir: 'dist',
            emptyOutDir: true,
            sourcemap: !isProduction,
            rolldownOptions: {
                output: {
                    entryFileNames: '[name].[hash].js',
                    chunkFileNames: '[name].[hash].js',
                    assetFileNames: '[name].[hash].[ext]',
                    codeSplitting: {
                        groups: [
                            {
                                name: 'lib',
                                test: libChunkPattern,
                            },
                            {
                                name: 'crypto',
                                test: cryptoChunkPattern,
                            },
                        ],
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
