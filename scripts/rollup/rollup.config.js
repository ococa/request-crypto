// 多文件
import {
  cjsInputFile,
  esmInputFile,
  getBaseRollupPlugins,
  getDistPath,
  getEntryPath,
  isDev, typesInputFile,
} from './utils'
import terser from '@rollup/plugin-terser'
import { dts } from "rollup-plugin-dts";


const inputPath = getEntryPath('index.ts')
const interfaceFile = getEntryPath(typesInputFile)
const outputPath = getDistPath()

console.log('interfaceFile', interfaceFile)

export default async () => ([{
    input: interfaceFile,
    output: [{ file: `${outputPath}/${typesInputFile}`, format: "es" }],
    plugins: [dts()],
},{
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
}])
