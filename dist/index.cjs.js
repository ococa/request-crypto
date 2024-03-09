'use strict'
var r = require('axios')
exports.createRequestInstance = (e, t = {}) => {
  const n = r.create(e)
  return (
    (function (r, e = {}) {
      const { encryptFn: t, decryptFn: n } = e
      t &&
        r.interceptors.request.use((r) => {
          const e = r.transformRequest
          if (!e) throw new Error(`request ${r} has no transformRequest`)
          if (!Array.isArray(e))
            throw new Error(`transformRequest ${e} is not an array`)
          if ((e.push(t), !n)) return r
          const s = r.transformResponse
          if (!s) throw new Error(`request ${r} has no transformResponse`)
          if ('function' != typeof n)
            throw new Error(`decryptFn ${n} is not a function`)
          if (!Array.isArray(s))
            throw new Error(`transformResponse ${s} is not an array`)
          return s.unshift(n), r
        })
    })(n, t),
    n
  )
}
