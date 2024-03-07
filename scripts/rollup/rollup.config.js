// 多文件
import { getBaseRollupPlugins, getDistPath, getEntryPath, isDev } from './utils'

const inputPath = getEntryPath('index.ts')
const outputPath = getDistPath()

export default async () => ({
  input: inputPath,
  output: [
    {
      file: `${outputPath}/index.cjs.js`,
      name: 'index.js',
      format: 'cjs',
    },
    {
      file: `${outputPath}/index.esm.js`,
      name: 'index.esm.js',
      format: 'es',
    },
  ],
  plugins: [
    ...getBaseRollupPlugins(),
    !isDev && (await import('@rollup/plugin-terser')).default(),
  ],
})
