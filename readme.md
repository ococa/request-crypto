
## 使用方式
```javascript

const instance = CreateCryptoInstance(
  {
  // axios options
  },
  'xxxxxx密钥', // sm2 非对称加密公钥, 加密密钥(公钥加密(客户端)，私钥解密（服务端）)
  false, // 可选参数， 是否使用非对称加密，开发环境调试用
); 

```