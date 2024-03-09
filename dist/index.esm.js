import r from"axios";const t=(t,n={})=>{const e=r.create(t);return function(r,t={}){const{encryptFn:n,decryptFn:e}=t;n&&r.interceptors.request.use((r=>{const t=r.transformRequest;if(!t)throw new Error(`request ${r} has no transformRequest`);if(!Array.isArray(t))throw new Error(`transformRequest ${t} is not an array`);if(t.push(n),!e)return r;const o=r.transformResponse;if(!o)throw new Error(`request ${r} has no transformResponse`);if("function"!=typeof e)throw new Error(`decryptFn ${e} is not a function`);if(!Array.isArray(o))throw new Error(`transformResponse ${o} is not an array`);return o.unshift(e),r}))}(e,n),e};const n=(r=16,t="high")=>{const n=["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"],e=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"],o=[0,1,2,3,4,5,6,7,8,9],s=["!","@","-","_","=","<",">","#","*","%","+","&","^","$"],a=[];let i="";const u=function(...r){let t="";return r.forEach((r=>{t+=r[Math.floor(Math.random()*r.length)]})),t};switch(t){case"high":i+=u(n,e,o,s),a.push(...n,...e,...o,...s);break;case"medium":i+=u(n,e,o),a.push(...n,...e,...o);break;default:i+=u(n,o),a.push(...n,...o)}const c=r-i.length;for(let r=0;r<c;r++)i+=u(a);return i},e=r=>{const t=n(16,"high");return{info:{key:t,algorithm:r||"SM4"},key:[Number(t)]}},o=()=>({mode:"ecb",padding:"pkcs#7",output:"array"});export{t as createRequestInstance,e as getCryptoInfo,o as getSm4EncryptConfig,n as randomPassword};
