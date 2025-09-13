const path = require('path')
const TerserPlugin = require('terser-webpack-plugin')
const { CleanWebpackPlugin } = require('clean-webpack-plugin')
const MiniCssExtractPlugin = require('mini-css-extract-plugin')
const defaultConfig = require("@wordpress/scripts/config/webpack.config");

// Check if we're in watch mode
const isWatchMode = process.argv.includes('--watch');
const isProduction = process.argv.includes('--mode=production');

console.log('Watch mode:', isWatchMode, 'Production:', isProduction);

module.exports = {
    ...defaultConfig,
    entry: {
        'drivetestpage': './src/googledrive-page/main.jsx', 
    },

    output: {
        path: path.resolve(__dirname, 'assets'),
        filename: 'js/[name].min.js',
        publicPath: '../../',
        assetModuleFilename: 'images/[name][ext][query]',
        clean: false, // ADDED: Disable webpack 5 auto-clean
    },

    resolve: {
        extensions: ['.js', '.jsx'],
    },

    module: {
        ...defaultConfig.module,
        rules: [
            ...defaultConfig.module.rules,
            {
                test: /\.(js|jsx)$/,
                exclude: /node_modules/,
                use: 'babel-loader',
            },
            {
                test: /\.(css|scss)$/,
                exclude: /node_modules/,
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader,
                        options: {
                            esModule: false,
                        },
                    },
                    {
                        loader: 'css-loader',
                    },
                    'sass-loader',
                ],
            },
            {
                test: /\.svg/,
                type: 'asset/inline',
            },
            {
                test: /\.(png|jpg|gif)$/,
                type: 'asset/resource',
                generator: {
                    filename: 'images/[name][ext][query]',
                },
            },
            {
                test: /\.(woff|woff2|eot|ttf|otf)$/,
                type: 'asset/resource',
                generator: {
                    filename: 'fonts/[name][ext][query]',
                },
            },
        ],
    },

    plugins: [
        // COMPLETELY REMOVE all CleanWebpackPlugin instances
        ...defaultConfig.plugins.filter(plugin => 
            plugin.constructor.name !== 'CleanWebpackPlugin'
        ),
        
        // ONLY add custom CleanWebpackPlugin for production builds
        ...(isProduction && !isWatchMode ? [
            new CleanWebpackPlugin({
                cleanOnceBeforeBuildPatterns: [
                    'js/drivetestpage.*',
                    'css/drivetestpage.*',
                ],
                cleanStaleWebpackAssets: false,
                verbose: true,
                dry: false,
            })
        ] : []),

        new MiniCssExtractPlugin({
            filename: 'css/[name].min.css',
        }),
    ],

    optimization: {
        minimize: isProduction,
        minimizer: [
            new TerserPlugin({
                terserOptions: {
                    format: {
                        comments: false,
                    },
                },
                extractComments: false,
            }),
        ],
    },
}