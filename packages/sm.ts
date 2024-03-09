// 对称加密方法 information 生成
import { randomPassword } from './utils'

const getCryptoInfo = (password: string) => {
  const psd = password || randomPassword(16, 'high')
  const key = [...Buffer.from(psd)]
  const info = {
    key: psd,
    algorithm: 'SM4',
  }

  return {
    info,
    key,
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

const getSm4EncryptConfig = () => {
  return {
    mode: 'ecb',
    padding: 'pkcs#7',
    output: 'array',
  }
}

export { getCryptoInfo, getSm4EncryptConfig }
