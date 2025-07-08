// Docker-specific webpack configuration with minimal TypeScript checking
const path = require("path");
const webpack = require("webpack");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

const repo = __dirname;

const config = {
  mode: 'production',
  bail: false,
  entry: {
    bundle: path.join(repo, "frontend/index.jsx"),
  },
  output: {
    path: path.join(repo, "assets/"),
    publicPath: "/assets/",
    filename: "[name].js",
  },
  plugins: [
    new HtmlWebpackPlugin({
      filename: "../frontend/templates/react.tmpl",
      inject: false,
      templateParameters: {
        isProduction: true,
      },
      template: "frontend/templates/react.ejs",
    }),
    new MiniCssExtractPlugin({
      filename: "bundle.css",
    }),
  ],
  stats: 'minimal',
  module: {
    rules: [
      {
        test: /\.(pdf|png|gif|ico|jpg|svg|eot|otf|woff|woff2|ttf|mp4|webm)$/,
        type: "asset",
        generator: {
          filename: "[name]@[hash][ext]",
        },
      },
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: "esbuild-loader",
          options: {
            loader: "jsx",
            target: "es2016",
          },
        },
      },
      {
        test: /\.(ts|tsx)$/,
        exclude: /node_modules/,
        use: {
          loader: "esbuild-loader",
          options: {
            loader: "tsx",
            target: "es2016",
            tsconfigRaw: {
              compilerOptions: {
                allowJs: true,
                skipLibCheck: true,
                noImplicitAny: false,
                strict: false,
                noEmit: false,
                allowSyntheticDefaultImports: true,
                esModuleInterop: true,
                jsx: "react",
              },
            },
          },
        },
      },
      {
        test: /\.scss$/,
        use: [
          MiniCssExtractPlugin.loader,
          "css-loader",
          "sass-loader",
        ],
      },
      {
        test: /\.css$/,
        use: [
          MiniCssExtractPlugin.loader,
          "css-loader",
        ],
      },
    ],
  },
  resolve: {
    extensions: [".js", ".jsx", ".ts", ".tsx"],
  },
};

module.exports = config;
