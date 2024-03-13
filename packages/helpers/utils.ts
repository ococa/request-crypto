// 随机密钥生成，【用于对称加密】

import { randomPassType } from '../types'
import { AxiosRequestHeaders, AxiosResponseHeaders } from 'axios'

/**
 * 获取随机数
 * @param {number} len 随机数长度
 * @param {string} mode 随机数模式 high:高级 medium:中等 low:低等
 */
export const randomPassword: randomPassType = (
  len: number = 16,
  mode: string = 'high',
) => {
  const lowerCaseArr = [
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
  ]
  const blockLetterArr = [
    'A',
    'B',
    'C',
    'D',
    'E',
    'F',
    'G',
    'H',
    'I',
    'J',
    'K',
    'L',
    'M',
    'N',
    'O',
    'P',
    'Q',
    'R',
    'S',
    'T',
    'U',
    'V',
    'W',
    'X',
    'Y',
    'Z',
  ]
  const numberArr = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  const specialArr = [
    '!',
    '@',
    '-',
    '_',
    '=',
    '<',
    '>',
    '#',
    '*',
    '%',
    '+',
    '&',
    '^',
    '$',
  ]
  const passArr = []
  let password = ''

  //指定参数随机获取一个字符
  const specifyRandom = function (...arr: (string | number)[][]) {
    let str = ''
    arr.forEach((item) => {
      str += item[Math.floor(Math.random() * item.length)]
    })
    return str
  }

  switch (mode) {
    case 'high':
      //安全最高的
      password += specifyRandom(
        lowerCaseArr,
        blockLetterArr,
        numberArr,
        specialArr,
      )
      passArr.push(
        ...lowerCaseArr,
        ...blockLetterArr,
        ...numberArr,
        ...specialArr,
      )
      break
    case 'medium':
      //中等的
      password += specifyRandom(lowerCaseArr, blockLetterArr, numberArr)
      passArr.push(...lowerCaseArr, ...blockLetterArr, ...numberArr)
      break
    //低等的
    case 'low':
      password += specifyRandom(lowerCaseArr, numberArr)
      passArr.push(...lowerCaseArr, ...numberArr)
      break
    default:
      password += specifyRandom(lowerCaseArr, numberArr)
      passArr.push(...lowerCaseArr, ...numberArr)
  }

  const forLen = len - password.length
  for (let i = 0; i < forLen; i++) {
    password += specifyRandom(passArr)
  }

  return password
}

export const HEADER_ENCRYPT_KEY = 'X-Encrypt-Key'
export const HEADER_ENCRYPT_WITH = 'X-Encrypt-With'

export const setRequestCryptoHeader = (
  headers: AxiosRequestHeaders,
  encryptKey: string,
) => {
  headers.set(HEADER_ENCRYPT_KEY, encryptKey)
  return headers
}
export const isEncryptResponse = (headers: AxiosResponseHeaders) => {
  const headerValue = headers.get(HEADER_ENCRYPT_WITH)
  return (
    headerValue &&
    typeof headerValue === 'string' &&
    headerValue.toLowerCase() === 'sm4'
  )
}

export function ab2str(buf: ArrayBuffer, encoding = 'utf-8') {
  const enc = new TextDecoder(encoding)

  return enc.decode(buf)
}

export function transformResponseData(data: unknown) {
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data)
    } catch (e) {
      console.error('error', e)
      throw e
    }
  }
  if (data instanceof ArrayBuffer) {
    return ab2str(data)
  }
  return data
}

export function transformArrayBufferToJsonData(data: ArrayBuffer) {
  try {
    if (data instanceof ArrayBuffer) {
      return transformStringToJsonData(ab2str(data))
    }
    return data
  } catch (e) {
    console.error('error', e)
    throw e
  }
}

export function transformStringToJsonData(data: string) {
  try {
    if (typeof data === 'string') {
      return JSON.parse(data)
    }
    return data
  } catch (e) {
    console.error('transform string to JSON data', {
      data,
      e,
    })
    return data
  }
}

/**
 *  正则判断 排除下列字符串开头
 *  /api/logmanage
 *  /api/data-source
 *  /api/enterpriseadmin
 *  /api/componentmanager
 *  /api/spacemanager
 *  /api/filemanager
 *
 *  不加密
 *  /bi-api/api
 */
export const isEncryptListApi = (url: string) => {
  const reg =
    /^\/(api\/logmanage|api\/data-source|api\/enterpriseadmin|api\/componentmanager|api\/spacemanager|api\/filemanager)/
  return reg.test(url)
}

// 不加密名单
// start with /bi-api/api
export const encryptWhiteList = (url: string) => {
  const reg = /^\/bi-api\/api/
  return reg.test(url)
}

//  接口加密规则
export const shouldEncrypt = (url: string) => {
  // 默认全部加密
  let ret = true

  if (encryptWhiteList(url)) {
    return false
  }

  // api 开头默认不加密
  if (url.startsWith('/api')) {
    ret = false
    // 如果在名单列表则加密
    if (isEncryptListApi(url)) {
      ret = true
    }
  }
  return ret
}
