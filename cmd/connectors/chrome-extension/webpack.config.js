const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');


module.exports = {
  entry: {
    options: './src/options.js',
    background: './src/index.js'
    // Add other entry points if needed
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader'
        }
      }
    ]
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'src/manifest.json', to: 'manifest.json' },
        { from: 'assets', to: 'assets' },
        { from: 'src/options.html', to: 'options.html' },
        { from: 'assets/locales', to: '_locales' },
      ],
    }),
  ],
};