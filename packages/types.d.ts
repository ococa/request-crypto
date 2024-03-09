import { AxiosRequestTransformer, AxiosResponseTransformer } from 'axios'

export interface cryptoFnsType {
  // 加密
  encryptFn?: AxiosRequestTransformer
  // 解密
  decryptFn?: AxiosResponseTransformer
}
