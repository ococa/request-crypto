import { createDecryptFnType, createEncryptFnType } from '../types'
import { getCryptoInfo, getSm4EncryptConfig } from '../helpers/sm'
import { sm2, sm4 } from 'sm-crypto'
import {
  isEncryptResponse,
  setRequestCryptoHeader,
  transformStringToJsonData,
} from '../helpers/utils'
import buffer from 'buffer'

const sm4EncryptConfig = getSm4EncryptConfig()

const Buffer = buffer.Buffer

const createEncryptFn: createEncryptFnType = function (
  __store,
  asymmetricKey,
  mapStore,
  requestKey,
) {
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
      mapStore.set(requestKey, deepClone(encryptInfo))
      setRequestCryptoHeader(headers, '04' + encryptInfo)

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
          padding: 'pkcs#5',
        })
        return transformStringToJsonData(decryptData)
      } else {
        // 非加密数据不处理
        return data
      }
    } catch (e) {
      console.error('decrypt error', e, data, headers)
    }
  }
}

// function isSameObject(obj1: object | undefined, obj2: object) {
//   if (obj1 === undefined) {
//     return false
//   }
//   const ret = JSON.stringify(obj1) === JSON.stringify(obj2)
//   console.log('is same object ', ret, { obj1, obj2 })
//   return ret
// }

function deepClone(obj: object | string) {
  if (typeof obj === 'string') {
    return String(obj)
  }
  return JSON.parse(JSON.stringify(obj))
}

export { createDecryptFn, createEncryptFn }
