const production = process.env.NODE_ENV == 'production'

export default {
    plugins: {
        'postcss-import': {},
        'postcss-url': {},
        '@tailwindcss/postcss': {},
        ...(production ? { cssnano: {} } : {}),
    },
}
