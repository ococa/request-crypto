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
import {
  isEncryptResponse,
  setRequestCryptoHeader,
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
