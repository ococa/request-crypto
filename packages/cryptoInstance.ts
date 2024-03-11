import { AxiosRequestHeaders } from 'axios'
import buffer from 'buffer'
import { sm2, sm4 } from 'sm-crypto'

import { createCryptoAxiosInstanceType, getCryptoInfoType } from './types'
import { ab2str, isEncryptResponse, setRequestCryptoHeader } from './utils'
import { getCryptoInfo, getSm4EncryptConfig } from './sm'
import { createRequestInstance } from './instance'

const Buffer = buffer.Buffer

// 存储每一次请求随机生成的对称加密需要的key 和 加密方法
const __store: {
  info: ReturnType<getCryptoInfoType>
  publicKey: number[]
} = {
  info: getCryptoInfo(),
  publicKey: [],
}

const sm4EncryptConfig = getSm4EncryptConfig()

const createCryptoAxiosInstance: createCryptoAxiosInstanceType = (
  options,
  asymmetricKey,
) => {
  if (!asymmetricKey || typeof asymmetricKey !== 'string') {
    throw new Error(
      `publicKey is required and must be a string ${asymmetricKey}`,
    )
  }
  const request = createRequestInstance(options, {
    encryptFn: (data, headers) => {
      if (headers.closeCrypto) {
        return data
      }
      __store.info = getCryptoInfo()
      __store.publicKey = [...Buffer.from(__store.info.key)]
      const encryptInfo = sm2.doEncrypt(
        JSON.stringify(__store.info),
        asymmetricKey,
        1,
      )
      setRequestCryptoHeader(headers, encryptInfo)

      console.log('--- 1 before request', __store.info.key, data, headers)
      if (data) {
        if (typeof data !== 'string') {
          data = JSON.stringify(data)
        }
        // __store.info = getCryptoInfo()
        // __store.publicKey = [...Buffer.from(__store.info.key)]
        console.log('=== body 加密原文 ===', data)
        const array = sm4.encrypt(
          data,
          __store.publicKey,
          sm4EncryptConfig as never,
        )
        console.log('=== body 加密结果 ===', array)
        data = Buffer.from(array)

        const decryptData = sm4.decrypt(array, __store.publicKey, {
          mode: 'ecb' as never,
          padding: 'pkcs#7',
        })
        console.log('=== 加密前 解密测试 encryptInfo ===', {
          encryptInfo,
          obj: JSON.stringify(__store.info),
          decryptData,
          asymmetricKey,
        })
        return data
      } else {
        return data
      }
    },
    decryptFn: (data, headers) => {
      if (isEncryptResponse(headers)) {
        const arrayData = Buffer.from(data)
        const decryptData = sm4.decrypt(arrayData as never, __store.publicKey, {
          mode: 'ecb' as never,
          padding: 'pkcs#7',
        })
        if (typeof decryptData == 'string') {
          const rootData = JSON.parse(decryptData)
          const currentPage = rootData?.data?.total
          if (currentPage !== undefined) {
            rootData.data.list = rootData.data.content
            return rootData
          }
          return rootData
        }

        return decryptData
      }

      if (data instanceof ArrayBuffer) {
        const ret = ab2str(data)
        console.log('response data ===', ret)
        return ret
      }
      return data
    },
  })

  request.interceptors.request.use((config) => {
    const headers = config.headers as AxiosRequestHeaders
    if (!headers.closeCrypto) {
      config.responseType = 'arraybuffer'
    }
    return config
  })
  return request
}

export { createCryptoAxiosInstance }
