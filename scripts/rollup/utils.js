import path from 'path'
import ts from 'rollup-plugin-typescript2'
import cjs from '@rollup/plugin-commonjs'
import replace from '@rollup/plugin-replace'
import generatePackageJson from 'rollup-plugin-generate-package-json'

export const cjsInputFile = 'index.cjs.js'
export const esmInputFile = 'index.esm.js'

export const isDev = process.env.NODE_ENV === 'development'

const projectRootPath = path.resolve(__dirname, '../../')
const packagesPath = path.resolve(__dirname, '../../packages')

function getEntryPath(fileName) {
  return `${packagesPath}/${fileName}`
}

function getDistPath() {
  return path.join(projectRootPath, '/dist')
}
const distPath = getDistPath()

function getBaseRollupPlugins({
  tsConfig = {},
  alias = { __DEV__: isDev },
} = {}) {
  return [
    replace({
      preventAssignment: true,
      ...alias,
    }),
    cjs(),
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

export { getEntryPath, getDistPath, getBaseRollupPlugins }
