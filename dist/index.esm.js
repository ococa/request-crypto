import r from 'axios'
const n = (n, t = {}) => {
  const o = r.create(n)
  return (
    (function (r, n = {}) {
      const { encryptFn: t, decryptFn: o } = n
      t &&
        r.interceptors.request.use((r) => {
          const n = r.transformRequest
          if (!n) throw new Error(`request ${r} has no transformRequest`)
          if (!Array.isArray(n))
            throw new Error(`transformRequest ${n} is not an array`)
          if ((n.push(t), !o)) return r
          const e = r.transformResponse
          if (!e) throw new Error(`request ${r} has no transformResponse`)
          if ('function' != typeof o)
            throw new Error(`decryptFn ${o} is not a function`)
          if (!Array.isArray(e))
            throw new Error(`transformResponse ${e} is not an array`)
          return e.unshift(o), r
        })
    })(o, t),
    o
  )
}
export { n as createRequestInstance }
