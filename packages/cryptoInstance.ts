import axios, {
  AxiosInstance,
  AxiosRequestHeaders,
  CreateAxiosDefaults,
} from 'axios'
import buffer from 'buffer'
import { sm2, sm4 } from 'sm-crypto'

import {
  createCryptoAxiosInstanceType,
  createDecryptFnType,
  createEncryptFnType,
  storeType,
} from './types'
import { ab2str, isEncryptResponse, setRequestCryptoHeader } from './utils'
import { getCryptoInfo, getSm4EncryptConfig } from './sm'

const Buffer = buffer.Buffer

const sm4EncryptConfig = getSm4EncryptConfig()

const createCryptoAxiosInstance: createCryptoAxiosInstanceType = <T>(
  options: CreateAxiosDefaults<T> | undefined,
  asymmetricKey: string,
) => {
  const instance = axios.create(options)

  addEncryptFnToTransformRequest(instance, asymmetricKey)

  return instance
}

const createEncryptFn: createEncryptFnType = function (__store, asymmetricKey) {
  return (data, headers) => {
    try {
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
    } catch (e) {
      console.error('encrypt error', e, data, headers)
    }
  }
}
const createDecryptFn: createDecryptFnType = function (__store) {
  return (data, headers) => {
    try {
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
    } catch (e) {
      console.error('decrypt error', e, data, headers)
    }
  }
}
function addEncryptFnToTransformRequest(
  instance: AxiosInstance,
  asymmetricKey: string,
) {
  instance.interceptors.request.use((config) => {
    const headers = config.headers as AxiosRequestHeaders
    if (!headers.closeCrypto) {
      config.responseType = 'arraybuffer'
    }
    return config
  })

  instance.interceptors.request.use((value) => {
    const transformRequest = value.transformRequest
    const __store: storeType = {
      info: null,
      publicKey: [],
    }
    if (!transformRequest) {
      throw new Error(`request ${value} has no transformRequest`)
    }
    if (Array.isArray(transformRequest)) {
      transformRequest.push(createEncryptFn(__store, asymmetricKey))
    } else {
      throw new Error(`transformRequest ${transformRequest} is not an array`)
    }

    const decryptFn = createDecryptFn(__store)
    if (!decryptFn) {
      return value
    }
    const transformResponse = value.transformResponse
    if (!transformResponse) {
      throw new Error(`request ${value} has no transformResponse`)
    }
    if (typeof decryptFn !== 'function') {
      throw new Error(`decryptFn ${decryptFn} is not a function`)
    }
    if (Array.isArray(transformResponse)) {
      transformResponse.unshift(decryptFn)
    } else {
      throw new Error(`transformResponse ${transformResponse} is not an array`)
    }
    return value
  })
}

export { createCryptoAxiosInstance }
