// 对称加密方法 information 生成
import { randomPassword } from './utils'
import { getCryptoInfoType, getSm4EncryptConfigType } from './types'

const getCryptoInfo: getCryptoInfoType = <T>(algorithm?: T) => {
  const psd = randomPassword(16, 'high')
  const info = {
    randomPassword: psd,
    algorithm: algorithm || 'SM4',
  }

  return {
    ...info,
  }
}

// 对称加密解密方法

// 非对称加密加密方法
// function asymmetricEncrypt(
//   data: string,
//   publicKey: string,
//   fn: (...args: any) => any,
// ) {
//
// }

// 非对称加密解密方法
const getSm4EncryptConfig: getSm4EncryptConfigType = () => {
  return {
    mode: 'ecb',
    padding: 'pkcs#7',
    output: 'array',
  }
}

export { getCryptoInfo, getSm4EncryptConfig }
