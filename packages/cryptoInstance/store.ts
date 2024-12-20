import md5 from 'md5'
import { createMapStoreType, storeType } from '../types'
import { randomPassword } from '../helpers/utils'

const transformParamsToString = (
  url: string,
  params: Record<string, string>,
) => {
  // params order -> string
  const _url = new URL(window.location.origin + url)
  for (const key in params) {
    _url.searchParams.append(key, params[key])
  }
  return _url.toString()
  // params.append('param3', 'value3');
  // console.log(url.toString());
  // const keys = Object.keys(params).sort()
  // return keys.reduce((acc, key) => {
  //   return acc + key + params[key]
  // }, '')
}

export const createMapStore: createMapStoreType<storeType> = function <T>() {
  // 基于axios请求，存储加密信息
  const mapStore = new Map<string, T>()

  function get(key: string) {
    return mapStore.get(key)
  }

  function hashUrlValue(
    url: string,
    params: null | undefined | Record<string, string>,
  ) {
    try {
      const SALT = 'e0c7ff'
      const fetchUrl = transformParamsToString(url, params ?? {})
      return md5(fetchUrl + SALT)
    } catch (e) {
      console.error('error', e)
      return randomPassword(10)
    }
  }

  function set(key: string, value: T) {
    mapStore.set(key, value)
  }
  function clear(key: string) {
    mapStore.delete(key)
  }

  return {
    get,
    generateKey: hashUrlValue,
    set,
    clear,
  }
}
