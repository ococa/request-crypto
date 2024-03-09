import {
  AxiosInstance,
  AxiosRequestTransformer,
  AxiosResponseTransformer,
  CreateAxiosDefaults,
} from 'axios'

export { createRequestInstance } from './instance'
export { randomPassword } from './utils'
export { getCryptoInfo, getSm4EncryptConfig } from './sm'

export interface cryptoFnsType {
  // 加密
  encryptFn?: AxiosRequestTransformer
  // 解密
  decryptFn?: AxiosResponseTransformer
}

export interface createRequestInstanceType {
  <T>(
    options: CreateAxiosDefaults<T> | undefined,
    cryptoFns?: cryptoFnsType,
  ): AxiosInstance
}

export interface randomPassType {
  (length: number, mode?: 'low' | 'medium' | 'high'): string
}

export interface getCryptoInfoType {
  <T = string>(
    algorithm?: T,
  ): {
    key: string
    algorithm: T | string
  }
}

export interface getSm4EncryptConfigType {
  (): {
    padding?: 'none' | 'pkcs#5' | 'pkcs#7'
    mode?: 'cbc' | 'ecb'
    iv?: any
    output: 'string' | 'array'
  }
}
