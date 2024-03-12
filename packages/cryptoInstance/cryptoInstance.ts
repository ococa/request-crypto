import axios, { AxiosInstance, CreateAxiosDefaults } from 'axios'

import {
  createCryptoAxiosInstanceType,
  createMapStoreType,
  storeType,
} from '../types'
import {
  randomPassword,
  shouldEncrypt,
  transformArrayBufferToJsonData,
  transformResponseData,
  transformStringToJsonData,
} from '../helpers/utils'
import { createDecryptFn, createEncryptFn } from './cryptoFn'
import { sm2 } from 'sm-crypto'

const createMapStore: createMapStoreType<storeType> = function <T>() {
  // 基于axios请求，存储加密信息
  const mapStore = new Map<string, T>()

  function get(key: string) {
    return mapStore.get(key)
  }
  function randomKeyForMap(url: string) {
    const random = randomPassword(8, 'low')
    const key = `${random}-/${url}`
    if (mapStore.has(key)) {
      return randomKeyForMap(url)
    }
    return key
  }

  function set(key: string, value: T) {
    mapStore.set(key, value)
  }
  function clear(key: string) {
    mapStore.delete(key)
  }
  function sm() {
    return sm2
  }

  return {
    get,
    generateKey: randomKeyForMap,
    set,
    clear,
    sm,
  }
}

const mapStore = createMapStore()

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error
window.__map_store__ = mapStore

function addEncryptFnToTransformRequest(
  instance: AxiosInstance,
  asymmetricKey: string,
) {
  if (!asymmetricKey || typeof asymmetricKey !== 'string') {
    throw new Error(
      `publicKey is required and must be a string ${asymmetricKey}`,
    )
  }

  /**
   * 请求数据处理
   */
  // 5. 加密，解密添加 数据
  instance.interceptors.request.use((value) => {
    const transformRequest = value.transformRequest

    const requestKey = value?.headers?.__requestKey
    const __store: storeType = {
      info: null,
      publicKey: [],
    }
    if (!transformRequest) {
      throw new Error(`request ${value} has no transformRequest`)
    }
    if (Array.isArray(transformRequest)) {
      transformRequest.push(
        createEncryptFn(__store, asymmetricKey, mapStore, requestKey),
      )
    } else {
      throw new Error(`transformRequest ${transformRequest} is not an array`)
    }

    const decryptFn = createDecryptFn(__store, {
      mapStore,
      asymmetricKey,
      requestKey,
    })
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

  // 4. 加密
  instance.interceptors.request.use((config) => {
    const url = config.url
    const headers = config.headers
    if (!url) {
      return config
    }
    headers.__requestKey = mapStore.generateKey(url)
    return config
  })

  // 3. 非过滤数据返回类型声明
  instance.interceptors.request.use((config) => {
    const headers = config.headers
    if (!headers.closeCrypto) {
      config.responseType = 'arraybuffer'
    }
    return config
  })

  // 2. 过滤formData类型数据
  instance.interceptors.request.use((config) => {
    const data = config.data
    const headers = config.headers
    if (!data) {
      return config
    }
    if (data instanceof FormData) {
      headers.closeCrypto = true
    }
    return config
  })

  // 1. 通过url过滤
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
      headers.closeCrypto = true
    }
    return config
  })

  /**
   * 返回数据处理
   */
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
