import axios, { AxiosInstance, CreateAxiosDefaults } from 'axios'
import { createRequestInstanceType, cryptoFnsType } from '../types'

const createRequestInstance: createRequestInstanceType = <T>(
  options: CreateAxiosDefaults<T> | undefined,
  cryptoFns?: () => cryptoFnsType,
) => {
  const instance = axios.create(options)

  addEncryptFnToTransformRequest(instance, cryptoFns)

  return instance
}

function addEncryptFnToTransformRequest(
  instance: AxiosInstance,
  cryptoFns?: () => cryptoFnsType,
) {
  if (!cryptoFns) {
    return instance
  }
  const { encryptFn, decryptFn } = cryptoFns()

  if (encryptFn) {
    instance.interceptors.request.use((value) => {
      const transformRequest = value.transformRequest
      if (!transformRequest) {
        throw new Error(`request ${value} has no transformRequest`)
      }
      if (Array.isArray(transformRequest)) {
        transformRequest.push(encryptFn)
      } else {
        throw new Error(`transformRequest ${transformRequest} is not an array`)
      }

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
        throw new Error(
          `transformResponse ${transformResponse} is not an array`,
        )
      }
      return value
    })
  }
}

export { createRequestInstance }
