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

export interface createRequestInstance {
  <T>(
    options: CreateAxiosDefaults<T> | undefined,
    cryptoFns?: cryptoFnsType,
  ): AxiosInstance
}
