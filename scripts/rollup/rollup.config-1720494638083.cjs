'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var path = require('path');
var ts = require('rollup-plugin-typescript2');
var cjs = require('@rollup/plugin-commonjs');
var replace = require('@rollup/plugin-replace');
var generatePackageJson = require('rollup-plugin-generate-package-json');
var resolve = require('@rollup/plugin-node-resolve');
var json = require('@rollup/plugin-json');
var eslint = require('@rollup/plugin-eslint');
var terser = require('@rollup/plugin-terser');

const cjsInputFile = 'index.cjs.js';
const esmInputFile = 'index.esm.js';

const isDev = process.env.NODE_ENV === 'development';

const projectRootPath = path.resolve(__dirname, '../../');
const packagesPath = path.resolve(__dirname, '../../packages');

function getEntryPath(fileName) {
  return `${packagesPath}/${fileName}`
}

function getDistPath() {
  return path.join(projectRootPath, '/dist')
}
const distPath = getDistPath();

function getBaseRollupPlugins({
  tsConfig = {},
  alias = { __DEV__: isDev },
} = {}) {
  return [
    json(),
    resolve({
      browser: true,
      preferBuiltins: true,
    }),
    replace({
      preventAssignment: true,
      ...alias,
    }),
    cjs(),
    eslint(),
    ts(tsConfig),
    generatePackageJson({
      inputFolder: projectRootPath,
      outputFolder: distPath,
      baseContents: ({ name, description, version, dependencies = {} }) => ({
        name,
        description,
        version,
        main: cjsInputFile,
        module: esmInputFile,
        dependencies,
      }),
    }),
  ]
}

// 多文件

const inputPath = getEntryPath('index.ts');
const outputPath = getDistPath();

var rollup_config = async () => ({
  input: inputPath,
  output: [
    {
      file: `${outputPath}/${cjsInputFile}`,
      name: cjsInputFile,
      format: 'cjs',
    },
    {
      file: `${outputPath}/${esmInputFile}`,
      name: esmInputFile,
      format: 'es',
    },
  ],
  external: ['axios'],
  plugins: [...getBaseRollupPlugins(), !isDev && terser()],
});

exports.default = rollup_config;
