import { createDecryptFnType, createEncryptFnType } from '../types'
import { getCryptoInfo, getSm4EncryptConfig } from '../helpers/sm'
import { sm2, sm4 } from 'sm-crypto'
import {
  isEncryptResponse,
  setRequestCryptoHeader,
  transformArrayBufferToJsonData,
  transformStringToJsonData,
} from '../helpers/utils'
import buffer from 'buffer'

const sm4EncryptConfig = getSm4EncryptConfig()

const Buffer = buffer.Buffer

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

export { createDecryptFn, createEncryptFn }
