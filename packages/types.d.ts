import {
  AxiosInstance,
  AxiosRequestTransformer,
  AxiosResponseTransformer,
  CreateAxiosDefaults,
} from 'axios'

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
    info: {
      key: string
      algorithm: T | string
    }
    key: number[]
  }
}

export interface getSm4EncryptConfigType {
  (): {
    mode: string
    padding: string
    output: string
  }
}
