var webpack = require('webpack');
var path = require('path');
var appDir = path.join(__dirname, '..');

var moduleRoots = [
    [appDir, 'src'],
    [appDir, 'node_modules'],
    [process.env.SPLUNK_SOURCE || '', 'web', 'node_modules'],
    [process.env.SPLUNK_SOURCE || '', 'web', 'search_mrsparkle', 'exposed', 'js'],
    [process.env.SPLUNK_HOME || '', 'lib', 'node_modules'],
].map(function (parts) { return path.resolve(path.join.apply(path, parts)); });

var extensions = ['', '.js', '.es', '.jsx'];

module.exports = {
    resolve: {
        alias: {
            splunk_instrumentation: appDir + '/src'
        },
        root: moduleRoots,
        extensions: extensions
    },

    resolveLoader: {
        root: moduleRoots,
        extensions: extensions,
        alias: {
            "contrib/text": "raw-loader"
        }
    },

    plugins: [
        new webpack.ProvidePlugin({
            Promise: 'core-js/library/es6/promise'
        })
    ],

    entry:  appDir + '/src/SWA/swa.es',

    output: {
        "path": appDir + "/appserver/static/build/pages",
        "filename": "swa.js",
        "sourceMapFilename": "swa.map"
    },

    module: {
        loaders: [
            {
                test: /.es?$/,
                loader: 'babel-loader',
                exclude: /node_modules/,
                query: {
                    presets: ['es2015']
                }
            }
        ]
    }
}
