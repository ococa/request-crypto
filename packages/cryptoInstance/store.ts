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
      const _key = md5(fetchUrl + SALT)
      return `${_key}-/${url}`
    } catch (e) {
      if (__DEV__) {
        console.error('error', e)
      }
      const random = randomPassword(10)
      return `${random}-/${url}`
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
