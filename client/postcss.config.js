const production = process.env.NODE_ENV == 'production'

module.exports = {
    plugins: {
        'postcss-import': {},
        'postcss-url': {},
        '@tailwindcss/postcss': {},
        ...(production ? { cssnano: {} } : {}),
    },
}
