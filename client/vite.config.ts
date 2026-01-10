import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'
import sri from 'vite-plugin-sri-gen'

export default defineConfig(({ mode }) => {
    const isProduction = mode === 'production'

    return {
        plugins: [
            svelte(),
            VitePWA({
                registerType: 'autoUpdate',
                workbox: {
                    globPatterns: ['**/*.{js,css,html,svg,png,ico,woff,woff2}'],
                    globIgnores: ['**/*.map', '**/manifest*.json', '**/*.LICENSE.txt'],
                },
                manifest: {
                    name: 'Revaulter',
                    short_name: 'Revaulter',
                    theme_color: '#1e293b',
                    background_color: '#f8fafc',
                    display: 'standalone',
                    icons: [
                        {
                            src: '/icon-192.png',
                            sizes: '192x192',
                            type: 'image/png',
                        },
                        {
                            src: '/icon-512.png',
                            sizes: '512x512',
                            type: 'image/png',
                        },
                    ],
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
