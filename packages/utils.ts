// 随机密钥生成，【用于对称加密】

import { randomPassType } from './types'

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
