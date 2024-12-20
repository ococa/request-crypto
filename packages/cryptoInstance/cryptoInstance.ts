import axios, { AxiosInstance, CreateAxiosDefaults } from 'axios'

import { createCryptoAxiosInstanceType, storeType } from '../types'
import {
  HEADER_ENCRYPT_WITH,
  shouldEncrypt,
  transformResponseData,
  transformStringToJsonData,
} from '../helpers/utils'
import { createDecryptFn, createEncryptFn } from './cryptoFn'
import buffer from 'buffer'
import { createMapStore } from './store'

const storageLangKey = 'cps_lang'

const mapStore = createMapStore()

// window.__map_store__ = mapStore

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
    try {
      const url = encodeURI(config?.url ?? '')
      const headers = config.headers
      if (!url) {
        return config
      }
      headers.__requestKey = mapStore.generateKey(
        url,
        config?.params,
        headers?.get('Authorization') as string,
      )
      return config
    } catch (e) {
      console.error('error', e)
      return config
    }
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
    if (data instanceof FormData || data instanceof File) {
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
    (response) => {
      const { request, headers } = response
      // 加密过的数据已经被处理了
      if (headers && (headers as any).get(HEADER_ENCRYPT_WITH)) {
        return response
      }
      if (
        request?.responseType?.toLowerCase() === 'arraybuffer' ||
        request?.responseType?.toLowerCase() === 'blob'
      ) {
        // 特殊数据不处理，直接返回
        // do nothing ->>
      } else {
        response.data = transformStringToJsonData(response.data)
      }
      return response
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

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-expect-error
window.__buffer = buffer

const createCryptoAxiosInstance: createCryptoAxiosInstanceType = <T>(
  options: CreateAxiosDefaults<T> | undefined,
  asymmetricKey: string,
  isCloseDecrypt?: boolean,
) => {
  const instance = axios.create(options)
  instance.interceptors.request.use((config) => {
    const langKey = localStorage.getItem(storageLangKey) as 'en' | 'ko' | 'zh'
    const langMap = {
      en: 'en-US',
      ko: 'ko-KR',
      zh: 'zh-CN',
    }
    if (langKey && Object.prototype.hasOwnProperty.call(langMap, langKey)) {
      const langValue = langMap[langKey]
      // "accept-language": "",
      config.headers.set({
        'Accept-Language': `${langValue},zh;q=0.9,en;q=0.8`,
      })
    }
    return config
  })

  if (isCloseDecrypt) {
    return instance
  }

  addEncryptFnToTransformRequest(instance, asymmetricKey)

  return instance
}

export { createCryptoAxiosInstance }
