const webpack = require('webpack')
const MiniCssExtractPlugin = require('mini-css-extract-plugin')
const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const { SubresourceIntegrityPlugin } = require('webpack-subresource-integrity')
const { GenerateSW } = require('workbox-webpack-plugin')
const path = require('path')
const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin

const mode = process.env.NODE_ENV || 'development'
const prod = mode == 'production'
const analyze = process.env.ANALYZE == '1'

const htmlMinifyOptions = {
    collapseWhitespace: true,
    conservativeCollapse: true,
    removeComments: true,
    collapseBooleanAttributes: true,
    decodeEntities: true,
    html5: true,
    keepClosingSlash: false,
    processConditionalComments: true,
    removeEmptyAttributes: true,
}

module.exports = {
    entry: path.resolve(__dirname, 'src/main.ts'),
    resolve: {
        mainFields: ['svelte', 'browser', 'style', 'module', 'main'],
        extensions: ['.ts', '.mjs', '.js', '.svelte'],
        conditionNames: ['svelte', 'browser', 'require', 'node'],
    },
    output: {
        path: path.resolve(__dirname, 'dist/'),
        publicPath: '/',
        filename: prod ? '[name].[contenthash:8].js' : '[name].js',
        chunkFilename: prod ? '[name].[contenthash:8].js' : '[name].js',
        crossOriginLoading: 'anonymous',
    },
    optimization: {
        usedExports: true,
        moduleIds: 'deterministic',
        runtimeChunk: false,
    },
    module: {
        rules: [
            {
                test: /\.svelte$/,
                exclude: [],
                use: {
                    loader: 'svelte-loader',
                    options: {
                        hotReload: true,
                        compilerOptions: {
                            dev: !prod,
                        },
                    },
                },
            },
            {
                test: /\.ts$/,
                exclude: /node_modules/,
                use: {
                    loader: 'ts-loader',
                },
            },
            {
                test: /\.css$/,
                use: [
                    prod ? MiniCssExtractPlugin.loader : 'style-loader',
                    { loader: 'css-loader', options: { importLoaders: 1 } },
                    'postcss-loader',
                ],
            },
        ],
    },
    plugins: [
        // Cleanup dist folder
        new CleanWebpackPlugin({
            cleanOnceBeforeBuildPatterns: ['**/*'],
        }),

        // Extract CSS
        new MiniCssExtractPlugin({
            filename: '[name].[contenthash:8].css',
        }),

        // Definitions
        new webpack.DefinePlugin({
            PRODUCTION: prod,
            URL_PREFIX: process.env.URL_PREFIX ? JSON.stringify(process.env.URL_PREFIX) : `''`,
        }),

        // Enable subresource integrity check
        new SubresourceIntegrityPlugin(),

        // Generate the index page
        new HtmlWebpackPlugin({
            filename: 'index.html',
            template: path.resolve(__dirname, 'src/index.html'),
            minify: prod ? htmlMinifyOptions : false,
        }),

        // Generate a service worker in prod
        ...(prod
            ? [
                  new GenerateSW({
                      exclude: [/\.map$/, /^manifest.*\.js$/, /LICENSE\.txt$/],
                      swDest: 'sw.js',
                  }),
              ]
            : []),

        // Include the bundle analyzer only when mode is "analyze"
        ...(analyze ? [new BundleAnalyzerPlugin()] : []),
    ],
    mode,
    devServer: {
        port: 3000,
        // We can't use websockets over a proxy
        webSocketServer: false,
    },
    devtool: prod ? false : 'source-map',
}
