import { AxiosRequestTransformer, AxiosResponseTransformer, CreateAxiosDefaults, AxiosInstance } from 'axios';

interface cryptoFnsType {
  // 加密
  encryptFn?: AxiosRequestTransformer
  // 解密
  decryptFn?: AxiosResponseTransformer
}

interface createRequestInstanceType {
  <T>(
    options: CreateAxiosDefaults<T> | undefined,
    cryptoFns?: () => cryptoFnsType,
  ): AxiosInstance
}

interface createCryptoAxiosInstanceType {
  <T>(
    options: CreateAxiosDefaults<T> | undefined,
    asymmetricKey: string,
    isCloseDecrypt?: boolean,
  ): AxiosInstance
}

interface randomPassType {
  (length: number, mode?: 'low' | 'medium' | 'high'): string
}

interface getCryptoInfoType {
  <T = string>(
    algorithm?: T,
  ): {
    key: string
    algorithm: T | string
  }
}

interface getSm4EncryptConfigType {
  (): {
    padding?: 'none' | 'pkcs#5' | 'pkcs#7'
    mode?: 'cbc' | 'ecb'
    iv?: any
    output: 'string' | 'array'
  }
}

type createEncryptFnType = (
  storeInfo: storeType,
  asymmetricKey: string,
  mapStore: mapStoreType,
  requestKey: string,
) => AxiosRequestTransformer

type createDecryptFnType = (
  storeInfo: storeType,
  options?: {
    asymmetricKey?: string
    mapStore: mapStoreType
    requestKey: string
  },
) => AxiosResponseTransformer

type createMapStoreType<T> = () => {
  generateKey: (
    url: string,
    params: null | undefined | Record<string, string>,
    token: number | string | undefined | null,
  ) => string
  set: (key: string, value: T) => void
  get: (key: string) => T | undefined
  clear: (key: string) => void
}

type mapStoreType = ReturnType<createMapStoreType<storeType>>

type storeType = {
  info: ReturnType<getCryptoInfoType> | null
  publicKey: number[]
}

export type { createCryptoAxiosInstanceType, createDecryptFnType, createEncryptFnType, createRequestInstanceType, cryptoFnsType, getCryptoInfoType, getSm4EncryptConfigType, randomPassType, storeType };
