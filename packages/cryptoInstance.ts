import axios, { AxiosInstance, CreateAxiosDefaults } from 'axios'
import buffer from 'buffer'
import { sm2, sm4 } from 'sm-crypto'

import {
  createCryptoAxiosInstanceType,
  createDecryptFnType,
  createEncryptFnType,
  storeType,
} from './types'
import {
  isEncryptResponse,
  setRequestCryptoHeader,
  shouldEncrypt,
  transformArrayBufferToJsonData,
  transformResponseData,
  transformStringToJsonData,
} from './utils'
import { getCryptoInfo, getSm4EncryptConfig } from './sm'

const Buffer = buffer.Buffer

const sm4EncryptConfig = getSm4EncryptConfig()

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

      if (data) {
        if (typeof data !== 'string') {
          data = JSON.stringify(data)
        }
        const array = sm4.encrypt(
          data,
          __store.publicKey,
          sm4EncryptConfig as never,
        )
        data = Buffer.from(array)
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
        return transformStringToJsonData(decryptData)
      } else {
        return transformArrayBufferToJsonData(data)
      }
    } catch (e) {
      console.error('decrypt error', e, data, headers)
    }
  }
}

function addEncryptFnToTransformRequest(
  instance: AxiosInstance,
  asymmetricKey: string,
) {
  if (!asymmetricKey || typeof asymmetricKey !== 'string') {
    throw new Error(
      `publicKey is required and must be a string ${asymmetricKey}`,
    )
  }

  // 通过url过滤
  instance.interceptors.request.use((config) => {
    const url = config.url
    const headers = config.headers
    if (!url) {
      throw new Error('url is required')
    }
    if ({}.hasOwnProperty.call(headers, 'closeCrypto')) {
      return config
    }

    const encrypt = shouldEncrypt(url)
    if (!encrypt) {
      console.log(`url: ${url} shouldCloseCrypto: ${!encrypt}`)
      headers.closeCrypto = true
    }
    return config
  })

  // 过滤formData类型数据
  instance.interceptors.request.use((config) => {
    const data = config.data
    const headers = config.headers
    if (!data) {
      return config
    }
    if (data instanceof FormData) {
      console.log(`body of request: ${config.url} is FormData: ${data}`)
      headers.closeCrypto = true
    }
    return config
  })

  // 非过滤数据返回类型声明
  instance.interceptors.request.use((config) => {
    const headers = config.headers
    if (!headers.closeCrypto) {
      config.responseType = 'arraybuffer'
    }
    return config
  })

  // 加密，解密添加 数据
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

  // 返回数据转换
  instance.interceptors.response.use(
    (data) => {
      data.data = transformArrayBufferToJsonData(data.data)
      data.data = transformStringToJsonData(data.data)
      return data
    },
    (error) => {
      const response = error.response
      if (response?.data) {
        response.data = transformResponseData(response.data)
      }
      throw error
    },
  )
}

const createCryptoAxiosInstance: createCryptoAxiosInstanceType = <T>(
  options: CreateAxiosDefaults<T> | undefined,
  asymmetricKey: string,
) => {
  const instance = axios.create(options)

  addEncryptFnToTransformRequest(instance, asymmetricKey)

  return instance
}

export { createCryptoAxiosInstance }
