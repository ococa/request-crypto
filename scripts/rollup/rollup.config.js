// 多文件
import {
  cjsInputFile,
  esmInputFile,
  getBaseRollupPlugins,
  getDistPath,
  getEntryPath,
  isDev,
} from './utils'
import terser from '@rollup/plugin-terser'

const inputPath = getEntryPath('index.ts')
const outputPath = getDistPath()

export default async () => ({
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
})
