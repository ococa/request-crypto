import axios from 'axios';
import buffer from 'buffer';

const createRequestInstance = (options, cryptoFns) => {
    const instance = axios.create(options);
    addEncryptFnToTransformRequest$1(instance, cryptoFns);
    return instance;
};
function addEncryptFnToTransformRequest$1(instance, cryptoFns) {
    if (!cryptoFns) {
        return instance;
    }
    const { encryptFn, decryptFn } = cryptoFns();
    if (encryptFn) {
        instance.interceptors.request.use((value) => {
            const transformRequest = value.transformRequest;
            if (!transformRequest) {
                throw new Error(`request ${value} has no transformRequest`);
            }
            if (Array.isArray(transformRequest)) {
                transformRequest.push(encryptFn);
            }
            else {
                throw new Error(`transformRequest ${transformRequest} is not an array`);
            }
            if (!decryptFn) {
                return value;
            }
            const transformResponse = value.transformResponse;
            if (!transformResponse) {
                throw new Error(`request ${value} has no transformResponse`);
            }
            if (typeof decryptFn !== 'function') {
                throw new Error(`decryptFn ${decryptFn} is not a function`);
            }
            if (Array.isArray(transformResponse)) {
                transformResponse.unshift(decryptFn);
            }
            else {
                throw new Error(`transformResponse ${transformResponse} is not an array`);
            }
            return value;
        });
    }
}

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

var jsbn = {exports: {}};

(function (module, exports) {
	(function(){

	    // Copyright (c) 2005  Tom Wu
	    // All Rights Reserved.
	    // See "LICENSE" for details.

	    // Basic JavaScript BN library - subset useful for RSA encryption.

	    // Bits per digit
	    var dbits;

	    // JavaScript engine analysis
	    var canary = 0xdeadbeefcafe;
	    var j_lm = ((canary&0xffffff)==0xefcafe);

	    // (public) Constructor
	    function BigInteger(a,b,c) {
	      if(a != null)
	        if("number" == typeof a) this.fromNumber(a,b,c);
	        else if(b == null && "string" != typeof a) this.fromString(a,256);
	        else this.fromString(a,b);
	    }

	    // return new, unset BigInteger
	    function nbi() { return new BigInteger(null); }

	    // am: Compute w_j += (x*this_i), propagate carries,
	    // c is initial carry, returns final carry.
	    // c < 3*dvalue, x < 2*dvalue, this_i < dvalue
	    // We need to select the fastest one that works in this environment.

	    // am1: use a single mult and divide to get the high bits,
	    // max digit bits should be 26 because
	    // max internal value = 2*dvalue^2-2*dvalue (< 2^53)
	    function am1(i,x,w,j,c,n) {
	      while(--n >= 0) {
	        var v = x*this[i++]+w[j]+c;
	        c = Math.floor(v/0x4000000);
	        w[j++] = v&0x3ffffff;
	      }
	      return c;
	    }
	    // am2 avoids a big mult-and-extract completely.
	    // Max digit bits should be <= 30 because we do bitwise ops
	    // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
	    function am2(i,x,w,j,c,n) {
	      var xl = x&0x7fff, xh = x>>15;
	      while(--n >= 0) {
	        var l = this[i]&0x7fff;
	        var h = this[i++]>>15;
	        var m = xh*l+h*xl;
	        l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
	        c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
	        w[j++] = l&0x3fffffff;
	      }
	      return c;
	    }
	    // Alternately, set max digit bits to 28 since some
	    // browsers slow down when dealing with 32-bit numbers.
	    function am3(i,x,w,j,c,n) {
	      var xl = x&0x3fff, xh = x>>14;
	      while(--n >= 0) {
	        var l = this[i]&0x3fff;
	        var h = this[i++]>>14;
	        var m = xh*l+h*xl;
	        l = xl*l+((m&0x3fff)<<14)+w[j]+c;
	        c = (l>>28)+(m>>14)+xh*h;
	        w[j++] = l&0xfffffff;
	      }
	      return c;
	    }
	    var inBrowser = typeof navigator !== "undefined";
	    if(inBrowser && j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
	      BigInteger.prototype.am = am2;
	      dbits = 30;
	    }
	    else if(inBrowser && j_lm && (navigator.appName != "Netscape")) {
	      BigInteger.prototype.am = am1;
	      dbits = 26;
	    }
	    else { // Mozilla/Netscape seems to prefer am3
	      BigInteger.prototype.am = am3;
	      dbits = 28;
	    }

	    BigInteger.prototype.DB = dbits;
	    BigInteger.prototype.DM = ((1<<dbits)-1);
	    BigInteger.prototype.DV = (1<<dbits);

	    var BI_FP = 52;
	    BigInteger.prototype.FV = Math.pow(2,BI_FP);
	    BigInteger.prototype.F1 = BI_FP-dbits;
	    BigInteger.prototype.F2 = 2*dbits-BI_FP;

	    // Digit conversions
	    var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
	    var BI_RC = new Array();
	    var rr,vv;
	    rr = "0".charCodeAt(0);
	    for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
	    rr = "a".charCodeAt(0);
	    for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
	    rr = "A".charCodeAt(0);
	    for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

	    function int2char(n) { return BI_RM.charAt(n); }
	    function intAt(s,i) {
	      var c = BI_RC[s.charCodeAt(i)];
	      return (c==null)?-1:c;
	    }

	    // (protected) copy this to r
	    function bnpCopyTo(r) {
	      for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
	      r.t = this.t;
	      r.s = this.s;
	    }

	    // (protected) set from integer value x, -DV <= x < DV
	    function bnpFromInt(x) {
	      this.t = 1;
	      this.s = (x<0)?-1:0;
	      if(x > 0) this[0] = x;
	      else if(x < -1) this[0] = x+this.DV;
	      else this.t = 0;
	    }

	    // return bigint initialized to value
	    function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

	    // (protected) set from string and radix
	    function bnpFromString(s,b) {
	      var k;
	      if(b == 16) k = 4;
	      else if(b == 8) k = 3;
	      else if(b == 256) k = 8; // byte array
	      else if(b == 2) k = 1;
	      else if(b == 32) k = 5;
	      else if(b == 4) k = 2;
	      else { this.fromRadix(s,b); return; }
	      this.t = 0;
	      this.s = 0;
	      var i = s.length, mi = false, sh = 0;
	      while(--i >= 0) {
	        var x = (k==8)?s[i]&0xff:intAt(s,i);
	        if(x < 0) {
	          if(s.charAt(i) == "-") mi = true;
	          continue;
	        }
	        mi = false;
	        if(sh == 0)
	          this[this.t++] = x;
	        else if(sh+k > this.DB) {
	          this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
	          this[this.t++] = (x>>(this.DB-sh));
	        }
	        else
	          this[this.t-1] |= x<<sh;
	        sh += k;
	        if(sh >= this.DB) sh -= this.DB;
	      }
	      if(k == 8 && (s[0]&0x80) != 0) {
	        this.s = -1;
	        if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
	      }
	      this.clamp();
	      if(mi) BigInteger.ZERO.subTo(this,this);
	    }

	    // (protected) clamp off excess high words
	    function bnpClamp() {
	      var c = this.s&this.DM;
	      while(this.t > 0 && this[this.t-1] == c) --this.t;
	    }

	    // (public) return string representation in given radix
	    function bnToString(b) {
	      if(this.s < 0) return "-"+this.negate().toString(b);
	      var k;
	      if(b == 16) k = 4;
	      else if(b == 8) k = 3;
	      else if(b == 2) k = 1;
	      else if(b == 32) k = 5;
	      else if(b == 4) k = 2;
	      else return this.toRadix(b);
	      var km = (1<<k)-1, d, m = false, r = "", i = this.t;
	      var p = this.DB-(i*this.DB)%k;
	      if(i-- > 0) {
	        if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
	        while(i >= 0) {
	          if(p < k) {
	            d = (this[i]&((1<<p)-1))<<(k-p);
	            d |= this[--i]>>(p+=this.DB-k);
	          }
	          else {
	            d = (this[i]>>(p-=k))&km;
	            if(p <= 0) { p += this.DB; --i; }
	          }
	          if(d > 0) m = true;
	          if(m) r += int2char(d);
	        }
	      }
	      return m?r:"0";
	    }

	    // (public) -this
	    function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

	    // (public) |this|
	    function bnAbs() { return (this.s<0)?this.negate():this; }

	    // (public) return + if this > a, - if this < a, 0 if equal
	    function bnCompareTo(a) {
	      var r = this.s-a.s;
	      if(r != 0) return r;
	      var i = this.t;
	      r = i-a.t;
	      if(r != 0) return (this.s<0)?-r:r;
	      while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
	      return 0;
	    }

	    // returns bit length of the integer x
	    function nbits(x) {
	      var r = 1, t;
	      if((t=x>>>16) != 0) { x = t; r += 16; }
	      if((t=x>>8) != 0) { x = t; r += 8; }
	      if((t=x>>4) != 0) { x = t; r += 4; }
	      if((t=x>>2) != 0) { x = t; r += 2; }
	      if((t=x>>1) != 0) { x = t; r += 1; }
	      return r;
	    }

	    // (public) return the number of bits in "this"
	    function bnBitLength() {
	      if(this.t <= 0) return 0;
	      return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
	    }

	    // (protected) r = this << n*DB
	    function bnpDLShiftTo(n,r) {
	      var i;
	      for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
	      for(i = n-1; i >= 0; --i) r[i] = 0;
	      r.t = this.t+n;
	      r.s = this.s;
	    }

	    // (protected) r = this >> n*DB
	    function bnpDRShiftTo(n,r) {
	      for(var i = n; i < this.t; ++i) r[i-n] = this[i];
	      r.t = Math.max(this.t-n,0);
	      r.s = this.s;
	    }

	    // (protected) r = this << n
	    function bnpLShiftTo(n,r) {
	      var bs = n%this.DB;
	      var cbs = this.DB-bs;
	      var bm = (1<<cbs)-1;
	      var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
	      for(i = this.t-1; i >= 0; --i) {
	        r[i+ds+1] = (this[i]>>cbs)|c;
	        c = (this[i]&bm)<<bs;
	      }
	      for(i = ds-1; i >= 0; --i) r[i] = 0;
	      r[ds] = c;
	      r.t = this.t+ds+1;
	      r.s = this.s;
	      r.clamp();
	    }

	    // (protected) r = this >> n
	    function bnpRShiftTo(n,r) {
	      r.s = this.s;
	      var ds = Math.floor(n/this.DB);
	      if(ds >= this.t) { r.t = 0; return; }
	      var bs = n%this.DB;
	      var cbs = this.DB-bs;
	      var bm = (1<<bs)-1;
	      r[0] = this[ds]>>bs;
	      for(var i = ds+1; i < this.t; ++i) {
	        r[i-ds-1] |= (this[i]&bm)<<cbs;
	        r[i-ds] = this[i]>>bs;
	      }
	      if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
	      r.t = this.t-ds;
	      r.clamp();
	    }

	    // (protected) r = this - a
	    function bnpSubTo(a,r) {
	      var i = 0, c = 0, m = Math.min(a.t,this.t);
	      while(i < m) {
	        c += this[i]-a[i];
	        r[i++] = c&this.DM;
	        c >>= this.DB;
	      }
	      if(a.t < this.t) {
	        c -= a.s;
	        while(i < this.t) {
	          c += this[i];
	          r[i++] = c&this.DM;
	          c >>= this.DB;
	        }
	        c += this.s;
	      }
	      else {
	        c += this.s;
	        while(i < a.t) {
	          c -= a[i];
	          r[i++] = c&this.DM;
	          c >>= this.DB;
	        }
	        c -= a.s;
	      }
	      r.s = (c<0)?-1:0;
	      if(c < -1) r[i++] = this.DV+c;
	      else if(c > 0) r[i++] = c;
	      r.t = i;
	      r.clamp();
	    }

	    // (protected) r = this * a, r != this,a (HAC 14.12)
	    // "this" should be the larger one if appropriate.
	    function bnpMultiplyTo(a,r) {
	      var x = this.abs(), y = a.abs();
	      var i = x.t;
	      r.t = i+y.t;
	      while(--i >= 0) r[i] = 0;
	      for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
	      r.s = 0;
	      r.clamp();
	      if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
	    }

	    // (protected) r = this^2, r != this (HAC 14.16)
	    function bnpSquareTo(r) {
	      var x = this.abs();
	      var i = r.t = 2*x.t;
	      while(--i >= 0) r[i] = 0;
	      for(i = 0; i < x.t-1; ++i) {
	        var c = x.am(i,x[i],r,2*i,0,1);
	        if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
	          r[i+x.t] -= x.DV;
	          r[i+x.t+1] = 1;
	        }
	      }
	      if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
	      r.s = 0;
	      r.clamp();
	    }

	    // (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
	    // r != q, this != m.  q or r may be null.
	    function bnpDivRemTo(m,q,r) {
	      var pm = m.abs();
	      if(pm.t <= 0) return;
	      var pt = this.abs();
	      if(pt.t < pm.t) {
	        if(q != null) q.fromInt(0);
	        if(r != null) this.copyTo(r);
	        return;
	      }
	      if(r == null) r = nbi();
	      var y = nbi(), ts = this.s, ms = m.s;
	      var nsh = this.DB-nbits(pm[pm.t-1]);   // normalize modulus
	      if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
	      else { pm.copyTo(y); pt.copyTo(r); }
	      var ys = y.t;
	      var y0 = y[ys-1];
	      if(y0 == 0) return;
	      var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
	      var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
	      var i = r.t, j = i-ys, t = (q==null)?nbi():q;
	      y.dlShiftTo(j,t);
	      if(r.compareTo(t) >= 0) {
	        r[r.t++] = 1;
	        r.subTo(t,r);
	      }
	      BigInteger.ONE.dlShiftTo(ys,t);
	      t.subTo(y,y);  // "negative" y so we can replace sub with am later
	      while(y.t < ys) y[y.t++] = 0;
	      while(--j >= 0) {
	        // Estimate quotient digit
	        var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
	        if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {   // Try it out
	          y.dlShiftTo(j,t);
	          r.subTo(t,r);
	          while(r[i] < --qd) r.subTo(t,r);
	        }
	      }
	      if(q != null) {
	        r.drShiftTo(ys,q);
	        if(ts != ms) BigInteger.ZERO.subTo(q,q);
	      }
	      r.t = ys;
	      r.clamp();
	      if(nsh > 0) r.rShiftTo(nsh,r); // Denormalize remainder
	      if(ts < 0) BigInteger.ZERO.subTo(r,r);
	    }

	    // (public) this mod a
	    function bnMod(a) {
	      var r = nbi();
	      this.abs().divRemTo(a,null,r);
	      if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
	      return r;
	    }

	    // Modular reduction using "classic" algorithm
	    function Classic(m) { this.m = m; }
	    function cConvert(x) {
	      if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
	      else return x;
	    }
	    function cRevert(x) { return x; }
	    function cReduce(x) { x.divRemTo(this.m,null,x); }
	    function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
	    function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

	    Classic.prototype.convert = cConvert;
	    Classic.prototype.revert = cRevert;
	    Classic.prototype.reduce = cReduce;
	    Classic.prototype.mulTo = cMulTo;
	    Classic.prototype.sqrTo = cSqrTo;

	    // (protected) return "-1/this % 2^DB"; useful for Mont. reduction
	    // justification:
	    //         xy == 1 (mod m)
	    //         xy =  1+km
	    //   xy(2-xy) = (1+km)(1-km)
	    // x[y(2-xy)] = 1-k^2m^2
	    // x[y(2-xy)] == 1 (mod m^2)
	    // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
	    // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
	    // JS multiply "overflows" differently from C/C++, so care is needed here.
	    function bnpInvDigit() {
	      if(this.t < 1) return 0;
	      var x = this[0];
	      if((x&1) == 0) return 0;
	      var y = x&3;       // y == 1/x mod 2^2
	      y = (y*(2-(x&0xf)*y))&0xf; // y == 1/x mod 2^4
	      y = (y*(2-(x&0xff)*y))&0xff;   // y == 1/x mod 2^8
	      y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;    // y == 1/x mod 2^16
	      // last step - calculate inverse mod DV directly;
	      // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
	      y = (y*(2-x*y%this.DV))%this.DV;       // y == 1/x mod 2^dbits
	      // we really want the negative inverse, and -DV < y < DV
	      return (y>0)?this.DV-y:-y;
	    }

	    // Montgomery reduction
	    function Montgomery(m) {
	      this.m = m;
	      this.mp = m.invDigit();
	      this.mpl = this.mp&0x7fff;
	      this.mph = this.mp>>15;
	      this.um = (1<<(m.DB-15))-1;
	      this.mt2 = 2*m.t;
	    }

	    // xR mod m
	    function montConvert(x) {
	      var r = nbi();
	      x.abs().dlShiftTo(this.m.t,r);
	      r.divRemTo(this.m,null,r);
	      if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
	      return r;
	    }

	    // x/R mod m
	    function montRevert(x) {
	      var r = nbi();
	      x.copyTo(r);
	      this.reduce(r);
	      return r;
	    }

	    // x = x/R mod m (HAC 14.32)
	    function montReduce(x) {
	      while(x.t <= this.mt2) // pad x so am has enough room later
	        x[x.t++] = 0;
	      for(var i = 0; i < this.m.t; ++i) {
	        // faster way of calculating u0 = x[i]*mp mod DV
	        var j = x[i]&0x7fff;
	        var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
	        // use am to combine the multiply-shift-add into one call
	        j = i+this.m.t;
	        x[j] += this.m.am(0,u0,x,i,0,this.m.t);
	        // propagate carry
	        while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
	      }
	      x.clamp();
	      x.drShiftTo(this.m.t,x);
	      if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
	    }

	    // r = "x^2/R mod m"; x != r
	    function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

	    // r = "xy/R mod m"; x,y != r
	    function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

	    Montgomery.prototype.convert = montConvert;
	    Montgomery.prototype.revert = montRevert;
	    Montgomery.prototype.reduce = montReduce;
	    Montgomery.prototype.mulTo = montMulTo;
	    Montgomery.prototype.sqrTo = montSqrTo;

	    // (protected) true iff this is even
	    function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

	    // (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
	    function bnpExp(e,z) {
	      if(e > 0xffffffff || e < 1) return BigInteger.ONE;
	      var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
	      g.copyTo(r);
	      while(--i >= 0) {
	        z.sqrTo(r,r2);
	        if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
	        else { var t = r; r = r2; r2 = t; }
	      }
	      return z.revert(r);
	    }

	    // (public) this^e % m, 0 <= e < 2^32
	    function bnModPowInt(e,m) {
	      var z;
	      if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
	      return this.exp(e,z);
	    }

	    // protected
	    BigInteger.prototype.copyTo = bnpCopyTo;
	    BigInteger.prototype.fromInt = bnpFromInt;
	    BigInteger.prototype.fromString = bnpFromString;
	    BigInteger.prototype.clamp = bnpClamp;
	    BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
	    BigInteger.prototype.drShiftTo = bnpDRShiftTo;
	    BigInteger.prototype.lShiftTo = bnpLShiftTo;
	    BigInteger.prototype.rShiftTo = bnpRShiftTo;
	    BigInteger.prototype.subTo = bnpSubTo;
	    BigInteger.prototype.multiplyTo = bnpMultiplyTo;
	    BigInteger.prototype.squareTo = bnpSquareTo;
	    BigInteger.prototype.divRemTo = bnpDivRemTo;
	    BigInteger.prototype.invDigit = bnpInvDigit;
	    BigInteger.prototype.isEven = bnpIsEven;
	    BigInteger.prototype.exp = bnpExp;

	    // public
	    BigInteger.prototype.toString = bnToString;
	    BigInteger.prototype.negate = bnNegate;
	    BigInteger.prototype.abs = bnAbs;
	    BigInteger.prototype.compareTo = bnCompareTo;
	    BigInteger.prototype.bitLength = bnBitLength;
	    BigInteger.prototype.mod = bnMod;
	    BigInteger.prototype.modPowInt = bnModPowInt;

	    // "constants"
	    BigInteger.ZERO = nbv(0);
	    BigInteger.ONE = nbv(1);

	    // Copyright (c) 2005-2009  Tom Wu
	    // All Rights Reserved.
	    // See "LICENSE" for details.

	    // Extended JavaScript BN functions, required for RSA private ops.

	    // Version 1.1: new BigInteger("0", 10) returns "proper" zero
	    // Version 1.2: square() API, isProbablePrime fix

	    // (public)
	    function bnClone() { var r = nbi(); this.copyTo(r); return r; }

	    // (public) return value as integer
	    function bnIntValue() {
	      if(this.s < 0) {
	        if(this.t == 1) return this[0]-this.DV;
	        else if(this.t == 0) return -1;
	      }
	      else if(this.t == 1) return this[0];
	      else if(this.t == 0) return 0;
	      // assumes 16 < DB < 32
	      return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
	    }

	    // (public) return value as byte
	    function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

	    // (public) return value as short (assumes DB>=16)
	    function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

	    // (protected) return x s.t. r^x < DV
	    function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

	    // (public) 0 if this == 0, 1 if this > 0
	    function bnSigNum() {
	      if(this.s < 0) return -1;
	      else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
	      else return 1;
	    }

	    // (protected) convert to radix string
	    function bnpToRadix(b) {
	      if(b == null) b = 10;
	      if(this.signum() == 0 || b < 2 || b > 36) return "0";
	      var cs = this.chunkSize(b);
	      var a = Math.pow(b,cs);
	      var d = nbv(a), y = nbi(), z = nbi(), r = "";
	      this.divRemTo(d,y,z);
	      while(y.signum() > 0) {
	        r = (a+z.intValue()).toString(b).substr(1) + r;
	        y.divRemTo(d,y,z);
	      }
	      return z.intValue().toString(b) + r;
	    }

	    // (protected) convert from radix string
	    function bnpFromRadix(s,b) {
	      this.fromInt(0);
	      if(b == null) b = 10;
	      var cs = this.chunkSize(b);
	      var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
	      for(var i = 0; i < s.length; ++i) {
	        var x = intAt(s,i);
	        if(x < 0) {
	          if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
	          continue;
	        }
	        w = b*w+x;
	        if(++j >= cs) {
	          this.dMultiply(d);
	          this.dAddOffset(w,0);
	          j = 0;
	          w = 0;
	        }
	      }
	      if(j > 0) {
	        this.dMultiply(Math.pow(b,j));
	        this.dAddOffset(w,0);
	      }
	      if(mi) BigInteger.ZERO.subTo(this,this);
	    }

	    // (protected) alternate constructor
	    function bnpFromNumber(a,b,c) {
	      if("number" == typeof b) {
	        // new BigInteger(int,int,RNG)
	        if(a < 2) this.fromInt(1);
	        else {
	          this.fromNumber(a,c);
	          if(!this.testBit(a-1))    // force MSB set
	            this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
	          if(this.isEven()) this.dAddOffset(1,0); // force odd
	          while(!this.isProbablePrime(b)) {
	            this.dAddOffset(2,0);
	            if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
	          }
	        }
	      }
	      else {
	        // new BigInteger(int,RNG)
	        var x = new Array(), t = a&7;
	        x.length = (a>>3)+1;
	        b.nextBytes(x);
	        if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
	        this.fromString(x,256);
	      }
	    }

	    // (public) convert to bigendian byte array
	    function bnToByteArray() {
	      var i = this.t, r = new Array();
	      r[0] = this.s;
	      var p = this.DB-(i*this.DB)%8, d, k = 0;
	      if(i-- > 0) {
	        if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
	          r[k++] = d|(this.s<<(this.DB-p));
	        while(i >= 0) {
	          if(p < 8) {
	            d = (this[i]&((1<<p)-1))<<(8-p);
	            d |= this[--i]>>(p+=this.DB-8);
	          }
	          else {
	            d = (this[i]>>(p-=8))&0xff;
	            if(p <= 0) { p += this.DB; --i; }
	          }
	          if((d&0x80) != 0) d |= -256;
	          if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
	          if(k > 0 || d != this.s) r[k++] = d;
	        }
	      }
	      return r;
	    }

	    function bnEquals(a) { return(this.compareTo(a)==0); }
	    function bnMin(a) { return (this.compareTo(a)<0)?this:a; }
	    function bnMax(a) { return (this.compareTo(a)>0)?this:a; }

	    // (protected) r = this op a (bitwise)
	    function bnpBitwiseTo(a,op,r) {
	      var i, f, m = Math.min(a.t,this.t);
	      for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
	      if(a.t < this.t) {
	        f = a.s&this.DM;
	        for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
	        r.t = this.t;
	      }
	      else {
	        f = this.s&this.DM;
	        for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
	        r.t = a.t;
	      }
	      r.s = op(this.s,a.s);
	      r.clamp();
	    }

	    // (public) this & a
	    function op_and(x,y) { return x&y; }
	    function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

	    // (public) this | a
	    function op_or(x,y) { return x|y; }
	    function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

	    // (public) this ^ a
	    function op_xor(x,y) { return x^y; }
	    function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

	    // (public) this & ~a
	    function op_andnot(x,y) { return x&~y; }
	    function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

	    // (public) ~this
	    function bnNot() {
	      var r = nbi();
	      for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
	      r.t = this.t;
	      r.s = ~this.s;
	      return r;
	    }

	    // (public) this << n
	    function bnShiftLeft(n) {
	      var r = nbi();
	      if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
	      return r;
	    }

	    // (public) this >> n
	    function bnShiftRight(n) {
	      var r = nbi();
	      if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
	      return r;
	    }

	    // return index of lowest 1-bit in x, x < 2^31
	    function lbit(x) {
	      if(x == 0) return -1;
	      var r = 0;
	      if((x&0xffff) == 0) { x >>= 16; r += 16; }
	      if((x&0xff) == 0) { x >>= 8; r += 8; }
	      if((x&0xf) == 0) { x >>= 4; r += 4; }
	      if((x&3) == 0) { x >>= 2; r += 2; }
	      if((x&1) == 0) ++r;
	      return r;
	    }

	    // (public) returns index of lowest 1-bit (or -1 if none)
	    function bnGetLowestSetBit() {
	      for(var i = 0; i < this.t; ++i)
	        if(this[i] != 0) return i*this.DB+lbit(this[i]);
	      if(this.s < 0) return this.t*this.DB;
	      return -1;
	    }

	    // return number of 1 bits in x
	    function cbit(x) {
	      var r = 0;
	      while(x != 0) { x &= x-1; ++r; }
	      return r;
	    }

	    // (public) return number of set bits
	    function bnBitCount() {
	      var r = 0, x = this.s&this.DM;
	      for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
	      return r;
	    }

	    // (public) true iff nth bit is set
	    function bnTestBit(n) {
	      var j = Math.floor(n/this.DB);
	      if(j >= this.t) return(this.s!=0);
	      return((this[j]&(1<<(n%this.DB)))!=0);
	    }

	    // (protected) this op (1<<n)
	    function bnpChangeBit(n,op) {
	      var r = BigInteger.ONE.shiftLeft(n);
	      this.bitwiseTo(r,op,r);
	      return r;
	    }

	    // (public) this | (1<<n)
	    function bnSetBit(n) { return this.changeBit(n,op_or); }

	    // (public) this & ~(1<<n)
	    function bnClearBit(n) { return this.changeBit(n,op_andnot); }

	    // (public) this ^ (1<<n)
	    function bnFlipBit(n) { return this.changeBit(n,op_xor); }

	    // (protected) r = this + a
	    function bnpAddTo(a,r) {
	      var i = 0, c = 0, m = Math.min(a.t,this.t);
	      while(i < m) {
	        c += this[i]+a[i];
	        r[i++] = c&this.DM;
	        c >>= this.DB;
	      }
	      if(a.t < this.t) {
	        c += a.s;
	        while(i < this.t) {
	          c += this[i];
	          r[i++] = c&this.DM;
	          c >>= this.DB;
	        }
	        c += this.s;
	      }
	      else {
	        c += this.s;
	        while(i < a.t) {
	          c += a[i];
	          r[i++] = c&this.DM;
	          c >>= this.DB;
	        }
	        c += a.s;
	      }
	      r.s = (c<0)?-1:0;
	      if(c > 0) r[i++] = c;
	      else if(c < -1) r[i++] = this.DV+c;
	      r.t = i;
	      r.clamp();
	    }

	    // (public) this + a
	    function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

	    // (public) this - a
	    function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

	    // (public) this * a
	    function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

	    // (public) this^2
	    function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

	    // (public) this / a
	    function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

	    // (public) this % a
	    function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

	    // (public) [this/a,this%a]
	    function bnDivideAndRemainder(a) {
	      var q = nbi(), r = nbi();
	      this.divRemTo(a,q,r);
	      return new Array(q,r);
	    }

	    // (protected) this *= n, this >= 0, 1 < n < DV
	    function bnpDMultiply(n) {
	      this[this.t] = this.am(0,n-1,this,0,0,this.t);
	      ++this.t;
	      this.clamp();
	    }

	    // (protected) this += n << w words, this >= 0
	    function bnpDAddOffset(n,w) {
	      if(n == 0) return;
	      while(this.t <= w) this[this.t++] = 0;
	      this[w] += n;
	      while(this[w] >= this.DV) {
	        this[w] -= this.DV;
	        if(++w >= this.t) this[this.t++] = 0;
	        ++this[w];
	      }
	    }

	    // A "null" reducer
	    function NullExp() {}
	    function nNop(x) { return x; }
	    function nMulTo(x,y,r) { x.multiplyTo(y,r); }
	    function nSqrTo(x,r) { x.squareTo(r); }

	    NullExp.prototype.convert = nNop;
	    NullExp.prototype.revert = nNop;
	    NullExp.prototype.mulTo = nMulTo;
	    NullExp.prototype.sqrTo = nSqrTo;

	    // (public) this^e
	    function bnPow(e) { return this.exp(e,new NullExp()); }

	    // (protected) r = lower n words of "this * a", a.t <= n
	    // "this" should be the larger one if appropriate.
	    function bnpMultiplyLowerTo(a,n,r) {
	      var i = Math.min(this.t+a.t,n);
	      r.s = 0; // assumes a,this >= 0
	      r.t = i;
	      while(i > 0) r[--i] = 0;
	      var j;
	      for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
	      for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
	      r.clamp();
	    }

	    // (protected) r = "this * a" without lower n words, n > 0
	    // "this" should be the larger one if appropriate.
	    function bnpMultiplyUpperTo(a,n,r) {
	      --n;
	      var i = r.t = this.t+a.t-n;
	      r.s = 0; // assumes a,this >= 0
	      while(--i >= 0) r[i] = 0;
	      for(i = Math.max(n-this.t,0); i < a.t; ++i)
	        r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
	      r.clamp();
	      r.drShiftTo(1,r);
	    }

	    // Barrett modular reduction
	    function Barrett(m) {
	      // setup Barrett
	      this.r2 = nbi();
	      this.q3 = nbi();
	      BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
	      this.mu = this.r2.divide(m);
	      this.m = m;
	    }

	    function barrettConvert(x) {
	      if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
	      else if(x.compareTo(this.m) < 0) return x;
	      else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
	    }

	    function barrettRevert(x) { return x; }

	    // x = x mod m (HAC 14.42)
	    function barrettReduce(x) {
	      x.drShiftTo(this.m.t-1,this.r2);
	      if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
	      this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
	      this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
	      while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
	      x.subTo(this.r2,x);
	      while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
	    }

	    // r = x^2 mod m; x != r
	    function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

	    // r = x*y mod m; x,y != r
	    function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

	    Barrett.prototype.convert = barrettConvert;
	    Barrett.prototype.revert = barrettRevert;
	    Barrett.prototype.reduce = barrettReduce;
	    Barrett.prototype.mulTo = barrettMulTo;
	    Barrett.prototype.sqrTo = barrettSqrTo;

	    // (public) this^e % m (HAC 14.85)
	    function bnModPow(e,m) {
	      var i = e.bitLength(), k, r = nbv(1), z;
	      if(i <= 0) return r;
	      else if(i < 18) k = 1;
	      else if(i < 48) k = 3;
	      else if(i < 144) k = 4;
	      else if(i < 768) k = 5;
	      else k = 6;
	      if(i < 8)
	        z = new Classic(m);
	      else if(m.isEven())
	        z = new Barrett(m);
	      else
	        z = new Montgomery(m);

	      // precomputation
	      var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
	      g[1] = z.convert(this);
	      if(k > 1) {
	        var g2 = nbi();
	        z.sqrTo(g[1],g2);
	        while(n <= km) {
	          g[n] = nbi();
	          z.mulTo(g2,g[n-2],g[n]);
	          n += 2;
	        }
	      }

	      var j = e.t-1, w, is1 = true, r2 = nbi(), t;
	      i = nbits(e[j])-1;
	      while(j >= 0) {
	        if(i >= k1) w = (e[j]>>(i-k1))&km;
	        else {
	          w = (e[j]&((1<<(i+1))-1))<<(k1-i);
	          if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
	        }

	        n = k;
	        while((w&1) == 0) { w >>= 1; --n; }
	        if((i -= n) < 0) { i += this.DB; --j; }
	        if(is1) {    // ret == 1, don't bother squaring or multiplying it
	          g[w].copyTo(r);
	          is1 = false;
	        }
	        else {
	          while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
	          if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
	          z.mulTo(r2,g[w],r);
	        }

	        while(j >= 0 && (e[j]&(1<<i)) == 0) {
	          z.sqrTo(r,r2); t = r; r = r2; r2 = t;
	          if(--i < 0) { i = this.DB-1; --j; }
	        }
	      }
	      return z.revert(r);
	    }

	    // (public) gcd(this,a) (HAC 14.54)
	    function bnGCD(a) {
	      var x = (this.s<0)?this.negate():this.clone();
	      var y = (a.s<0)?a.negate():a.clone();
	      if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
	      var i = x.getLowestSetBit(), g = y.getLowestSetBit();
	      if(g < 0) return x;
	      if(i < g) g = i;
	      if(g > 0) {
	        x.rShiftTo(g,x);
	        y.rShiftTo(g,y);
	      }
	      while(x.signum() > 0) {
	        if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
	        if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
	        if(x.compareTo(y) >= 0) {
	          x.subTo(y,x);
	          x.rShiftTo(1,x);
	        }
	        else {
	          y.subTo(x,y);
	          y.rShiftTo(1,y);
	        }
	      }
	      if(g > 0) y.lShiftTo(g,y);
	      return y;
	    }

	    // (protected) this % n, n < 2^26
	    function bnpModInt(n) {
	      if(n <= 0) return 0;
	      var d = this.DV%n, r = (this.s<0)?n-1:0;
	      if(this.t > 0)
	        if(d == 0) r = this[0]%n;
	        else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
	      return r;
	    }

	    // (public) 1/this % m (HAC 14.61)
	    function bnModInverse(m) {
	      var ac = m.isEven();
	      if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
	      var u = m.clone(), v = this.clone();
	      var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
	      while(u.signum() != 0) {
	        while(u.isEven()) {
	          u.rShiftTo(1,u);
	          if(ac) {
	            if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
	            a.rShiftTo(1,a);
	          }
	          else if(!b.isEven()) b.subTo(m,b);
	          b.rShiftTo(1,b);
	        }
	        while(v.isEven()) {
	          v.rShiftTo(1,v);
	          if(ac) {
	            if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
	            c.rShiftTo(1,c);
	          }
	          else if(!d.isEven()) d.subTo(m,d);
	          d.rShiftTo(1,d);
	        }
	        if(u.compareTo(v) >= 0) {
	          u.subTo(v,u);
	          if(ac) a.subTo(c,a);
	          b.subTo(d,b);
	        }
	        else {
	          v.subTo(u,v);
	          if(ac) c.subTo(a,c);
	          d.subTo(b,d);
	        }
	      }
	      if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
	      if(d.compareTo(m) >= 0) return d.subtract(m);
	      if(d.signum() < 0) d.addTo(m,d); else return d;
	      if(d.signum() < 0) return d.add(m); else return d;
	    }

	    var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
	    var lplim = (1<<26)/lowprimes[lowprimes.length-1];

	    // (public) test primality with certainty >= 1-.5^t
	    function bnIsProbablePrime(t) {
	      var i, x = this.abs();
	      if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
	        for(i = 0; i < lowprimes.length; ++i)
	          if(x[0] == lowprimes[i]) return true;
	        return false;
	      }
	      if(x.isEven()) return false;
	      i = 1;
	      while(i < lowprimes.length) {
	        var m = lowprimes[i], j = i+1;
	        while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
	        m = x.modInt(m);
	        while(i < j) if(m%lowprimes[i++] == 0) return false;
	      }
	      return x.millerRabin(t);
	    }

	    // (protected) true if probably prime (HAC 4.24, Miller-Rabin)
	    function bnpMillerRabin(t) {
	      var n1 = this.subtract(BigInteger.ONE);
	      var k = n1.getLowestSetBit();
	      if(k <= 0) return false;
	      var r = n1.shiftRight(k);
	      t = (t+1)>>1;
	      if(t > lowprimes.length) t = lowprimes.length;
	      var a = nbi();
	      for(var i = 0; i < t; ++i) {
	        //Pick bases at random, instead of starting at 2
	        a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
	        var y = a.modPow(r,this);
	        if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
	          var j = 1;
	          while(j++ < k && y.compareTo(n1) != 0) {
	            y = y.modPowInt(2,this);
	            if(y.compareTo(BigInteger.ONE) == 0) return false;
	          }
	          if(y.compareTo(n1) != 0) return false;
	        }
	      }
	      return true;
	    }

	    // protected
	    BigInteger.prototype.chunkSize = bnpChunkSize;
	    BigInteger.prototype.toRadix = bnpToRadix;
	    BigInteger.prototype.fromRadix = bnpFromRadix;
	    BigInteger.prototype.fromNumber = bnpFromNumber;
	    BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
	    BigInteger.prototype.changeBit = bnpChangeBit;
	    BigInteger.prototype.addTo = bnpAddTo;
	    BigInteger.prototype.dMultiply = bnpDMultiply;
	    BigInteger.prototype.dAddOffset = bnpDAddOffset;
	    BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
	    BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
	    BigInteger.prototype.modInt = bnpModInt;
	    BigInteger.prototype.millerRabin = bnpMillerRabin;

	    // public
	    BigInteger.prototype.clone = bnClone;
	    BigInteger.prototype.intValue = bnIntValue;
	    BigInteger.prototype.byteValue = bnByteValue;
	    BigInteger.prototype.shortValue = bnShortValue;
	    BigInteger.prototype.signum = bnSigNum;
	    BigInteger.prototype.toByteArray = bnToByteArray;
	    BigInteger.prototype.equals = bnEquals;
	    BigInteger.prototype.min = bnMin;
	    BigInteger.prototype.max = bnMax;
	    BigInteger.prototype.and = bnAnd;
	    BigInteger.prototype.or = bnOr;
	    BigInteger.prototype.xor = bnXor;
	    BigInteger.prototype.andNot = bnAndNot;
	    BigInteger.prototype.not = bnNot;
	    BigInteger.prototype.shiftLeft = bnShiftLeft;
	    BigInteger.prototype.shiftRight = bnShiftRight;
	    BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
	    BigInteger.prototype.bitCount = bnBitCount;
	    BigInteger.prototype.testBit = bnTestBit;
	    BigInteger.prototype.setBit = bnSetBit;
	    BigInteger.prototype.clearBit = bnClearBit;
	    BigInteger.prototype.flipBit = bnFlipBit;
	    BigInteger.prototype.add = bnAdd;
	    BigInteger.prototype.subtract = bnSubtract;
	    BigInteger.prototype.multiply = bnMultiply;
	    BigInteger.prototype.divide = bnDivide;
	    BigInteger.prototype.remainder = bnRemainder;
	    BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
	    BigInteger.prototype.modPow = bnModPow;
	    BigInteger.prototype.modInverse = bnModInverse;
	    BigInteger.prototype.pow = bnPow;
	    BigInteger.prototype.gcd = bnGCD;
	    BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

	    // JSBN-specific extension
	    BigInteger.prototype.square = bnSquare;

	    // Expose the Barrett function
	    BigInteger.prototype.Barrett = Barrett;

	    // BigInteger interfaces not implemented in jsbn:

	    // BigInteger(int signum, byte[] magnitude)
	    // double doubleValue()
	    // float floatValue()
	    // int hashCode()
	    // long longValue()
	    // static BigInteger valueOf(long val)

	    // Random number generator - requires a PRNG backend, e.g. prng4.js

	    // For best results, put code like
	    // <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
	    // in your main HTML document.

	    var rng_state;
	    var rng_pool;
	    var rng_pptr;

	    // Mix in a 32-bit integer into the pool
	    function rng_seed_int(x) {
	      rng_pool[rng_pptr++] ^= x & 255;
	      rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	      rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	      rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	      if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
	    }

	    // Mix in the current time (w/milliseconds) into the pool
	    function rng_seed_time() {
	      rng_seed_int(new Date().getTime());
	    }

	    // Initialize the pool with junk if needed.
	    if(rng_pool == null) {
	      rng_pool = new Array();
	      rng_pptr = 0;
	      var t;
	      if(typeof window !== "undefined" && window.crypto) {
	        if (window.crypto.getRandomValues) {
	          // Use webcrypto if available
	          var ua = new Uint8Array(32);
	          window.crypto.getRandomValues(ua);
	          for(t = 0; t < 32; ++t)
	            rng_pool[rng_pptr++] = ua[t];
	        }
	        else if(navigator.appName == "Netscape" && navigator.appVersion < "5") {
	          // Extract entropy (256 bits) from NS4 RNG if available
	          var z = window.crypto.random(32);
	          for(t = 0; t < z.length; ++t)
	            rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
	        }
	      }
	      while(rng_pptr < rng_psize) {  // extract some randomness from Math.random()
	        t = Math.floor(65536 * Math.random());
	        rng_pool[rng_pptr++] = t >>> 8;
	        rng_pool[rng_pptr++] = t & 255;
	      }
	      rng_pptr = 0;
	      rng_seed_time();
	      //rng_seed_int(window.screenX);
	      //rng_seed_int(window.screenY);
	    }

	    function rng_get_byte() {
	      if(rng_state == null) {
	        rng_seed_time();
	        rng_state = prng_newstate();
	        rng_state.init(rng_pool);
	        for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
	          rng_pool[rng_pptr] = 0;
	        rng_pptr = 0;
	        //rng_pool = null;
	      }
	      // TODO: allow reseeding after first request
	      return rng_state.next();
	    }

	    function rng_get_bytes(ba) {
	      var i;
	      for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
	    }

	    function SecureRandom() {}

	    SecureRandom.prototype.nextBytes = rng_get_bytes;

	    // prng4.js - uses Arcfour as a PRNG

	    function Arcfour() {
	      this.i = 0;
	      this.j = 0;
	      this.S = new Array();
	    }

	    // Initialize arcfour context from key, an array of ints, each from [0..255]
	    function ARC4init(key) {
	      var i, j, t;
	      for(i = 0; i < 256; ++i)
	        this.S[i] = i;
	      j = 0;
	      for(i = 0; i < 256; ++i) {
	        j = (j + this.S[i] + key[i % key.length]) & 255;
	        t = this.S[i];
	        this.S[i] = this.S[j];
	        this.S[j] = t;
	      }
	      this.i = 0;
	      this.j = 0;
	    }

	    function ARC4next() {
	      var t;
	      this.i = (this.i + 1) & 255;
	      this.j = (this.j + this.S[this.i]) & 255;
	      t = this.S[this.i];
	      this.S[this.i] = this.S[this.j];
	      this.S[this.j] = t;
	      return this.S[(t + this.S[this.i]) & 255];
	    }

	    Arcfour.prototype.init = ARC4init;
	    Arcfour.prototype.next = ARC4next;

	    // Plug in your RNG constructor here
	    function prng_newstate() {
	      return new Arcfour();
	    }

	    // Pool size must be a multiple of 4 and greater than 32.
	    // An array of bytes the size of the pool will be passed to init()
	    var rng_psize = 256;

	    {
	        module.exports = {
	            default: BigInteger,
	            BigInteger: BigInteger,
	            SecureRandom: SecureRandom,
	        };
	    }

	}).call(commonjsGlobal); 
} (jsbn));

var jsbnExports = jsbn.exports;

/* eslint-disable class-methods-use-this */

const {BigInteger: BigInteger$3} = jsbnExports;

function bigintToValue(bigint) {
  let h = bigint.toString(16);
  if (h[0] !== '-') {
    // 正数
    if (h.length % 2 === 1) h = '0' + h; // 补齐到整字节
    else if (!h.match(/^[0-7]/)) h = '00' + h; // 非0开头，则补一个全0字节
  } else {
    // 负数
    h = h.substr(1);

    let len = h.length;
    if (len % 2 === 1) len += 1; // 补齐到整字节
    else if (!h.match(/^[0-7]/)) len += 2; // 非0开头，则补一个全0字节

    let mask = '';
    for (let i = 0; i < len; i++) mask += 'f';
    mask = new BigInteger$3(mask, 16);

    // 对绝对值取反，加1
    h = mask.xor(bigint).add(BigInteger$3.ONE);
    h = h.toString(16).replace(/^-/, '');
  }
  return h
}

class ASN1Object {
  constructor() {
    this.tlv = null;
    this.t = '00';
    this.l = '00';
    this.v = '';
  }

  /**
   * 获取 der 编码比特流16进制串
   */
  getEncodedHex() {
    if (!this.tlv) {
      this.v = this.getValue();
      this.l = this.getLength();
      this.tlv = this.t + this.l + this.v;
    }
    return this.tlv
  }

  getLength() {
    const n = this.v.length / 2; // 字节数
    let nHex = n.toString(16);
    if (nHex.length % 2 === 1) nHex = '0' + nHex; // 补齐到整字节

    if (n < 128) {
      // 短格式，以 0 开头
      return nHex
    } else {
      // 长格式，以 1 开头
      const head = 128 + nHex.length / 2; // 1(1位) + 真正的长度占用字节数(7位) + 真正的长度
      return head.toString(16) + nHex
    }
  }

  getValue() {
    return ''
  }
}

class DERInteger extends ASN1Object {
  constructor(bigint) {
    super();

    this.t = '02'; // 整型标签说明
    if (bigint) this.v = bigintToValue(bigint);
  }

  getValue() {
    return this.v
  }
}

class DERSequence extends ASN1Object {
  constructor(asn1Array) {
    super();

    this.t = '30'; // 序列标签说明
    this.asn1Array = asn1Array;
  }

  getValue() {
    this.v = this.asn1Array.map(asn1Object => asn1Object.getEncodedHex()).join('');
    return this.v
  }
}

/**
 * 获取 l 占用字节数
 */
function getLenOfL(str, start) {
  if (+str[start + 2] < 8) return 1 // l 以0开头，则表示短格式，只占一个字节
  return +str.substr(start + 2, 2) & 0x7f + 1 // 长格式，取第一个字节后7位作为长度真正占用字节数，再加上本身
}

/**
 * 获取 l
 */
function getL(str, start) {
  // 获取 l
  const len = getLenOfL(str, start);
  const l = str.substr(start + 2, len * 2);

  if (!l) return -1
  const bigint = +l[0] < 8 ? new BigInteger$3(l, 16) : new BigInteger$3(l.substr(2), 16);

  return bigint.intValue()
}

/**
 * 获取 v 的位置
 */
function getStartOfV(str, start) {
  const len = getLenOfL(str, start);
  return start + (len + 1) * 2
}

var asn1 = {
  /**
   * ASN.1 der 编码，针对 sm2 签名
   */
  encodeDer(r, s) {
    const derR = new DERInteger(r);
    const derS = new DERInteger(s);
    const derSeq = new DERSequence([derR, derS]);

    return derSeq.getEncodedHex()
  },

  /**
   * 解析 ASN.1 der，针对 sm2 验签
   */
  decodeDer(input) {
    // 结构：
    // input = | tSeq | lSeq | vSeq |
    // vSeq = | tR | lR | vR | tS | lS | vS |
    const start = getStartOfV(input, 0);

    const vIndexR = getStartOfV(input, start);
    const lR = getL(input, start);
    const vR = input.substr(vIndexR, lR * 2);

    const nextStart = vIndexR + vR.length;
    const vIndexS = getStartOfV(input, nextStart);
    const lS = getL(input, nextStart);
    const vS = input.substr(vIndexS, lS * 2);

    const r = new BigInteger$3(vR, 16);
    const s = new BigInteger$3(vS, 16);

    return {r, s}
  }
};

/* eslint-disable no-case-declarations, max-len */

const {BigInteger: BigInteger$2} = jsbnExports;

/**
 * thanks for Tom Wu : http://www-cs-students.stanford.edu/~tjw/jsbn/
 *
 * Basic Javascript Elliptic Curve implementation
 * Ported loosely from BouncyCastle's Java EC code
 * Only Fp curves implemented for now
 */

const TWO = new BigInteger$2('2');
const THREE = new BigInteger$2('3');

/**
 * 椭圆曲线域元素
 */
class ECFieldElementFp {
  constructor(q, x) {
    this.x = x;
    this.q = q;
    // TODO if (x.compareTo(q) >= 0) error
  }

  /**
   * 判断相等
   */
  equals(other) {
    if (other === this) return true
    return (this.q.equals(other.q) && this.x.equals(other.x))
  }

  /**
   * 返回具体数值
   */
  toBigInteger() {
    return this.x
  }

  /**
   * 取反
   */
  negate() {
    return new ECFieldElementFp(this.q, this.x.negate().mod(this.q))
  }

  /**
   * 相加
   */
  add(b) {
    return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相减
   */
  subtract(b) {
    return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相乘
   */
  multiply(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q))
  }

  /**
   * 相除
   */
  divide(b) {
    return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q))
  }

  /**
   * 平方
   */
  square() {
    return new ECFieldElementFp(this.q, this.x.square().mod(this.q))
  }
}

class ECPointFp {
  constructor(curve, x, y, z) {
    this.curve = curve;
    this.x = x;
    this.y = y;
    // 标准射影坐标系：zinv == null 或 z * zinv == 1
    this.z = z == null ? BigInteger$2.ONE : z;
    this.zinv = null;
    // TODO: compression flag
  }

  getX() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

    return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q))
  }

  getY() {
    if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

    return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q))
  }

  /**
   * 判断相等
   */
  equals(other) {
    if (other === this) return true
    if (this.isInfinity()) return other.isInfinity()
    if (other.isInfinity()) return this.isInfinity()

    // u = y2 * z1 - y1 * z2
    const u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
    if (!u.equals(BigInteger$2.ZERO)) return false

    // v = x2 * z1 - x1 * z2
    const v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
    return v.equals(BigInteger$2.ZERO)
  }

  /**
   * 是否是无穷远点
   */
  isInfinity() {
    if ((this.x === null) && (this.y === null)) return true
    return this.z.equals(BigInteger$2.ZERO) && !this.y.toBigInteger().equals(BigInteger$2.ZERO)
  }

  /**
   * 取反，x 轴对称点
   */
  negate() {
    return new ECPointFp(this.curve, this.x, this.y.negate(), this.z)
  }

  /**
   * 相加
   *
   * 标准射影坐标系：
   *
   * λ1 = x1 * z2
   * λ2 = x2 * z1
   * λ3 = λ1 − λ2
   * λ4 = y1 * z2
   * λ5 = y2 * z1
   * λ6 = λ4 − λ5
   * λ7 = λ1 + λ2
   * λ8 = z1 * z2
   * λ9 = λ3^2
   * λ10 = λ3 * λ9
   * λ11 = λ8 * λ6^2 − λ7 * λ9
   * x3 = λ3 * λ11
   * y3 = λ6 * (λ9 * λ1 − λ11) − λ4 * λ10
   * z3 = λ10 * λ8
   */
  add(b) {
    if (this.isInfinity()) return b
    if (b.isInfinity()) return this

    const x1 = this.x.toBigInteger();
    const y1 = this.y.toBigInteger();
    const z1 = this.z;
    const x2 = b.x.toBigInteger();
    const y2 = b.y.toBigInteger();
    const z2 = b.z;
    const q = this.curve.q;

    const w1 = x1.multiply(z2).mod(q);
    const w2 = x2.multiply(z1).mod(q);
    const w3 = w1.subtract(w2);
    const w4 = y1.multiply(z2).mod(q);
    const w5 = y2.multiply(z1).mod(q);
    const w6 = w4.subtract(w5);

    if (BigInteger$2.ZERO.equals(w3)) {
      if (BigInteger$2.ZERO.equals(w6)) {
        return this.twice() // this == b，计算自加
      }
      return this.curve.infinity // this == -b，则返回无穷远点
    }

    const w7 = w1.add(w2);
    const w8 = z1.multiply(z2).mod(q);
    const w9 = w3.square().mod(q);
    const w10 = w3.multiply(w9).mod(q);
    const w11 = w8.multiply(w6.square()).subtract(w7.multiply(w9)).mod(q);

    const x3 = w3.multiply(w11).mod(q);
    const y3 = w6.multiply(w9.multiply(w1).subtract(w11)).subtract(w4.multiply(w10)).mod(q);
    const z3 = w10.multiply(w8).mod(q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3)
  }

  /**
   * 自加
   *
   * 标准射影坐标系：
   *
   * λ1 = 3 * x1^2 + a * z1^2
   * λ2 = 2 * y1 * z1
   * λ3 = y1^2
   * λ4 = λ3 * x1 * z1
   * λ5 = λ2^2
   * λ6 = λ1^2 − 8 * λ4
   * x3 = λ2 * λ6
   * y3 = λ1 * (4 * λ4 − λ6) − 2 * λ5 * λ3
   * z3 = λ2 * λ5
   */
  twice() {
    if (this.isInfinity()) return this
    if (!this.y.toBigInteger().signum()) return this.curve.infinity

    const x1 = this.x.toBigInteger();
    const y1 = this.y.toBigInteger();
    const z1 = this.z;
    const q = this.curve.q;
    const a = this.curve.a.toBigInteger();

    const w1 = x1.square().multiply(THREE).add(a.multiply(z1.square())).mod(q);
    const w2 = y1.shiftLeft(1).multiply(z1).mod(q);
    const w3 = y1.square().mod(q);
    const w4 = w3.multiply(x1).multiply(z1).mod(q);
    const w5 = w2.square().mod(q);
    const w6 = w1.square().subtract(w4.shiftLeft(3)).mod(q);

    const x3 = w2.multiply(w6).mod(q);
    const y3 = w1.multiply(w4.shiftLeft(2).subtract(w6)).subtract(w5.shiftLeft(1).multiply(w3)).mod(q);
    const z3 = w2.multiply(w5).mod(q);

    return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3)
  }

  /**
   * 倍点计算
   */
  multiply(k) {
    if (this.isInfinity()) return this
    if (!k.signum()) return this.curve.infinity

    // 使用加减法
    const k3 = k.multiply(THREE);
    const neg = this.negate();
    let Q = this;

    for (let i = k3.bitLength() - 2; i > 0; i--) {
      Q = Q.twice();

      const k3Bit = k3.testBit(i);
      const kBit = k.testBit(i);

      if (k3Bit !== kBit) {
        Q = Q.add(k3Bit ? this : neg);
      }
    }

    return Q
  }
}

/**
 * 椭圆曲线 y^2 = x^3 + ax + b
 */
let ECCurveFp$1 = class ECCurveFp {
  constructor(q, a, b) {
    this.q = q;
    this.a = this.fromBigInteger(a);
    this.b = this.fromBigInteger(b);
    this.infinity = new ECPointFp(this, null, null); // 无穷远点
  }

  /**
   * 判断两个椭圆曲线是否相等
   */
  equals(other) {
    if (other === this) return true
    return (this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b))
  }

  /**
   * 生成椭圆曲线域元素
   */
  fromBigInteger(x) {
    return new ECFieldElementFp(this.q, x)
  }

  /**
   * 解析 16 进制串为椭圆曲线点
   */
  decodePointHex(s) {
    switch (parseInt(s.substr(0, 2), 16)) {
      // 第一个字节
      case 0:
        return this.infinity
      case 2:
      case 3:
        // 压缩
        const x = this.fromBigInteger(new BigInteger$2(s.substr(2), 16));
        // 对 p ≡ 3 (mod4)，即存在正整数 u，使得 p = 4u + 3
        // 计算 y = (√ (x^3 + ax + b) % p)^(u + 1) modp
        let y = this.fromBigInteger(x.multiply(x.square()).add(
          x.multiply(this.a)
        ).add(this.b).toBigInteger()
          .modPow(
            this.q.divide(new BigInteger$2('4')).add(BigInteger$2.ONE), this.q
          ));
        // 算出结果 2 进制最后 1 位不等于第 1 个字节减 2 则取反
        if (!y.toBigInteger().mod(TWO).equals(new BigInteger$2(s.substr(0, 2), 16).subtract(TWO))) {
          y = y.negate();
        }
        return new ECPointFp(this, x, y)
      case 4:
      case 6:
      case 7:
        const len = (s.length - 2) / 2;
        const xHex = s.substr(2, len);
        const yHex = s.substr(len + 2, len);

        return new ECPointFp(this, this.fromBigInteger(new BigInteger$2(xHex, 16)), this.fromBigInteger(new BigInteger$2(yHex, 16)))
      default:
        // 不支持
        return null
    }
  }
};

var ec = {
  ECPointFp,
  ECCurveFp: ECCurveFp$1,
};

/* eslint-disable no-bitwise, no-mixed-operators, no-use-before-define, max-len */

const {BigInteger: BigInteger$1, SecureRandom} = jsbnExports;
const {ECCurveFp} = ec;

const rng = new SecureRandom();
const {curve: curve$1, G: G$1, n: n$1} = generateEcparam();

/**
 * 获取公共椭圆曲线
 */
function getGlobalCurve() {
  return curve$1
}

/**
 * 生成ecparam
 */
function generateEcparam() {
  // 椭圆曲线
  const p = new BigInteger$1('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
  const a = new BigInteger$1('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
  const b = new BigInteger$1('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
  const curve = new ECCurveFp(p, a, b);

  // 基点
  const gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
  const gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
  const G = curve.decodePointHex('04' + gxHex + gyHex);

  const n = new BigInteger$1('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

  return {curve, G, n}
}

/**
 * 生成密钥对：publicKey = privateKey * G
 */
function generateKeyPairHex(a, b, c) {
  const random = a ? new BigInteger$1(a, b, c) : new BigInteger$1(n$1.bitLength(), rng);
  const d = random.mod(n$1.subtract(BigInteger$1.ONE)).add(BigInteger$1.ONE); // 随机数
  const privateKey = leftPad$1(d.toString(16), 64);

  const P = G$1.multiply(d); // P = dG，p 为公钥，d 为私钥
  const Px = leftPad$1(P.getX().toBigInteger().toString(16), 64);
  const Py = leftPad$1(P.getY().toBigInteger().toString(16), 64);
  const publicKey = '04' + Px + Py;

  return {privateKey, publicKey}
}

/**
 * 生成压缩公钥
 */
function compressPublicKeyHex(s) {
  if (s.length !== 130) throw new Error('Invalid public key to compress')

  const len = (s.length - 2) / 2;
  const xHex = s.substr(2, len);
  const y = new BigInteger$1(s.substr(len + 2, len), 16);

  let prefix = '03';
  if (y.mod(new BigInteger$1('2')).equals(BigInteger$1.ZERO)) prefix = '02';

  return prefix + xHex
}

/**
 * utf8串转16进制串
 */
function utf8ToHex(input) {
  input = unescape(encodeURIComponent(input));

  const length = input.length;

  // 转换到字数组
  const words = [];
  for (let i = 0; i < length; i++) {
    words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
  }

  // 转换到16进制
  const hexChars = [];
  for (let i = 0; i < length; i++) {
    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    hexChars.push((bite >>> 4).toString(16));
    hexChars.push((bite & 0x0f).toString(16));
  }

  return hexChars.join('')
}

/**
 * 补全16进制字符串
 */
function leftPad$1(input, num) {
  if (input.length >= num) return input

  return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 转成16进制串
 */
function arrayToHex(arr) {
  return arr.map(item => {
    item = item.toString(16);
    return item.length === 1 ? '0' + item : item
  }).join('')
}

/**
 * 转成utf8串
 */
function arrayToUtf8$1(arr) {
  const words = [];
  let j = 0;
  for (let i = 0; i < arr.length * 2; i += 2) {
    words[i >>> 3] |= parseInt(arr[j], 10) << (24 - (i % 8) * 4);
    j++;
  }

  try {
    const latin1Chars = [];

    for (let i = 0; i < arr.length; i++) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      latin1Chars.push(String.fromCharCode(bite));
    }

    return decodeURIComponent(escape(latin1Chars.join('')))
  } catch (e) {
    throw new Error('Malformed UTF-8 data')
  }
}

/**
 * 转成字节数组
 */
function hexToArray$2(hexStr) {
  const words = [];
  let hexStrLength = hexStr.length;

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad$1(hexStr, hexStrLength + 1);
  }

  hexStrLength = hexStr.length;

  for (let i = 0; i < hexStrLength; i += 2) {
    words.push(parseInt(hexStr.substr(i, 2), 16));
  }
  return words
}

/**
 * 验证公钥是否为椭圆曲线上的点
 */
function verifyPublicKey(publicKey) {
  const point = curve$1.decodePointHex(publicKey);
  if (!point) return false

  const x = point.getX();
  const y = point.getY();

  // 验证 y^2 是否等于 x^3 + ax + b
  return y.square().equals(x.multiply(x.square()).add(x.multiply(curve$1.a)).add(curve$1.b))
}

/**
 * 验证公钥是否等价，等价返回true
 */
function comparePublicKeyHex(publicKey1, publicKey2) {
  const point1 = curve$1.decodePointHex(publicKey1);
  if (!point1) return false

  const point2 = curve$1.decodePointHex(publicKey2);
  if (!point2) return false

  return point1.equals(point2)
}

var utils = {
  getGlobalCurve,
  generateEcparam,
  generateKeyPairHex,
  compressPublicKeyHex,
  utf8ToHex,
  leftPad: leftPad$1,
  arrayToHex,
  arrayToUtf8: arrayToUtf8$1,
  hexToArray: hexToArray$2,
  verifyPublicKey,
  comparePublicKeyHex,
};

// 消息扩展
const W = new Uint32Array(68);
const M = new Uint32Array(64); // W'

/**
 * 循环左移
 */
function rotl$1(x, n) {
  const s = n & 31;
  return (x << s) | (x >>> (32 - s))
}

/**
 * 二进制异或运算
 */
function xor(x, y) {
  const result = [];
  for (let i = x.length - 1; i >= 0; i--) result[i] = (x[i] ^ y[i]) & 0xff;
  return result
}

/**
 * 压缩函数中的置换函数 P0(X) = X xor (X <<< 9) xor (X <<< 17)
 */
function P0(X) {
  return (X ^ rotl$1(X, 9)) ^ rotl$1(X, 17)
}

/**
 * 消息扩展中的置换函数 P1(X) = X xor (X <<< 15) xor (X <<< 23)
 */
function P1(X) {
  return (X ^ rotl$1(X, 15)) ^ rotl$1(X, 23)
}

/**
 * sm3 本体
 */
function sm3$2(array) {
  let len = array.length * 8;

  // k 是满足 len + 1 + k = 448mod512 的最小的非负整数
  let k = len % 512;
  // 如果 448 <= (512 % len) < 512，需要多补充 (len % 448) 比特'0'以满足总比特长度为512的倍数
  k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1;

  // 填充
  const kArr = new Array((k - 7) / 8);
  const lenArr = new Array(8);
  for (let i = 0, len = kArr.length; i < len; i++) kArr[i] = 0;
  for (let i = 0, len = lenArr.length; i < len; i++) lenArr[i] = 0;
  len = len.toString(2);
  for (let i = 7; i >= 0; i--) {
    if (len.length > 8) {
      const start = len.length - 8;
      lenArr[i] = parseInt(len.substr(start), 2);
      len = len.substr(0, start);
    } else if (len.length > 0) {
      lenArr[i] = parseInt(len, 2);
      len = '';
    }
  }
  const m = new Uint8Array([...array, 0x80, ...kArr, ...lenArr]);
  const dataView = new DataView(m.buffer, 0);

  // 迭代压缩
  const n = m.length / 64;
  const V = new Uint32Array([0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]);
  for (let i = 0; i < n; i++) {
    W.fill(0);
    M.fill(0);

    // 将消息分组B划分为 16 个字 W0， W1，……，W15
    const start = 16 * i;
    for (let j = 0; j < 16; j++) {
      W[j] = dataView.getUint32((start + j) * 4, false);
    }

    // W16 ～ W67：W[j] <- P1(W[j−16] xor W[j−9] xor (W[j−3] <<< 15)) xor (W[j−13] <<< 7) xor W[j−6]
    for (let j = 16; j < 68; j++) {
      W[j] = (P1((W[j - 16] ^ W[j - 9]) ^ rotl$1(W[j - 3], 15)) ^ rotl$1(W[j - 13], 7)) ^ W[j - 6];
    }

    // W′0 ～ W′63：W′[j] = W[j] xor W[j+4]
    for (let j = 0; j < 64; j++) {
      M[j] = W[j] ^ W[j + 4];
    }

    // 压缩
    const T1 = 0x79cc4519;
    const T2 = 0x7a879d8a;
    // 字寄存器
    let A = V[0];
    let B = V[1];
    let C = V[2];
    let D = V[3];
    let E = V[4];
    let F = V[5];
    let G = V[6];
    let H = V[7];
    // 中间变量
    let SS1;
    let SS2;
    let TT1;
    let TT2;
    let T;
    for (let j = 0; j < 64; j++) {
      T = j >= 0 && j <= 15 ? T1 : T2;
      SS1 = rotl$1(rotl$1(A, 12) + E + rotl$1(T, j), 7);
      SS2 = SS1 ^ rotl$1(A, 12);

      TT1 = (j >= 0 && j <= 15 ? ((A ^ B) ^ C) : (((A & B) | (A & C)) | (B & C))) + D + SS2 + M[j];
      TT2 = (j >= 0 && j <= 15 ? ((E ^ F) ^ G) : ((E & F) | ((~E) & G))) + H + SS1 + W[j];

      D = C;
      C = rotl$1(B, 9);
      B = A;
      A = TT1;
      H = G;
      G = rotl$1(F, 19);
      F = E;
      E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
  }

  // 转回 uint8
  const result = [];
  for (let i = 0, len = V.length; i < len; i++) {
    const word = V[i];
    result.push((word & 0xff000000) >>> 24, (word & 0xff0000) >>> 16, (word & 0xff00) >>> 8, word & 0xff);
  }

  return result
}

/**
 * hmac 实现
 */
const blockLen = 64;
const iPad = new Uint8Array(blockLen);
const oPad = new Uint8Array(blockLen);
for (let i = 0; i < blockLen; i++) {
  iPad[i] = 0x36;
  oPad[i] = 0x5c;
}
function hmac$1(input, key) {
  // 密钥填充
  if (key.length > blockLen) key = sm3$2(key);
  while (key.length < blockLen) key.push(0);

  const iPadKey = xor(key, iPad);
  const oPadKey = xor(key, oPad);

  const hash = sm3$2([...iPadKey, ...input]);
  return sm3$2([...oPadKey, ...hash])
}

var sm3_1$1 = {
  sm3: sm3$2,
  hmac: hmac$1,
};

/* eslint-disable no-use-before-define */

const {BigInteger} = jsbnExports;
const {encodeDer, decodeDer} = asn1;
const _ = utils;
const sm3$1 = sm3_1$1.sm3;

const {G, curve, n} = _.generateEcparam();
const C1C2C3 = 0;

/**
 * 加密
 */
function doEncrypt(msg, publicKey, cipherMode = 1) {
  msg = typeof msg === 'string' ? _.hexToArray(_.utf8ToHex(msg)) : Array.prototype.slice.call(msg);
  publicKey = _.getGlobalCurve().decodePointHex(publicKey); // 先将公钥转成点

  const keypair = _.generateKeyPairHex();
  const k = new BigInteger(keypair.privateKey, 16); // 随机数 k

  // c1 = k * G
  let c1 = keypair.publicKey;
  if (c1.length > 128) c1 = c1.substr(c1.length - 128);

  // (x2, y2) = k * publicKey
  const p = publicKey.multiply(k);
  const x2 = _.hexToArray(_.leftPad(p.getX().toBigInteger().toRadix(16), 64));
  const y2 = _.hexToArray(_.leftPad(p.getY().toBigInteger().toRadix(16), 64));

  // c3 = hash(x2 || msg || y2)
  const c3 = _.arrayToHex(sm3$1([].concat(x2, msg, y2)));

  let ct = 1;
  let offset = 0;
  let t = []; // 256 位
  const z = [].concat(x2, y2);
  const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
    t = sm3$1([...z, ct >> 24 & 0x00ff, ct >> 16 & 0x00ff, ct >> 8 & 0x00ff, ct & 0x00ff]);
    ct++;
    offset = 0;
  };
  nextT(); // 先生成 Ha1

  for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
    if (offset === t.length) nextT();

    // c2 = msg ^ t
    msg[i] ^= t[offset++] & 0xff;
  }
  const c2 = _.arrayToHex(msg);

  return cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2
}

/**
 * 解密
 */
function doDecrypt(encryptData, privateKey, cipherMode = 1, {
  output = 'string',
} = {}) {
  privateKey = new BigInteger(privateKey, 16);

  let c3 = encryptData.substr(128, 64);
  let c2 = encryptData.substr(128 + 64);

  if (cipherMode === C1C2C3) {
    c3 = encryptData.substr(encryptData.length - 64);
    c2 = encryptData.substr(128, encryptData.length - 128 - 64);
  }

  const msg = _.hexToArray(c2);
  const c1 = _.getGlobalCurve().decodePointHex('04' + encryptData.substr(0, 128));

  const p = c1.multiply(privateKey);
  const x2 = _.hexToArray(_.leftPad(p.getX().toBigInteger().toRadix(16), 64));
  const y2 = _.hexToArray(_.leftPad(p.getY().toBigInteger().toRadix(16), 64));

  let ct = 1;
  let offset = 0;
  let t = []; // 256 位
  const z = [].concat(x2, y2);
  const nextT = () => {
    // (1) Hai = hash(z || ct)
    // (2) ct++
    t = sm3$1([...z, ct >> 24 & 0x00ff, ct >> 16 & 0x00ff, ct >> 8 & 0x00ff, ct & 0x00ff]);
    ct++;
    offset = 0;
  };
  nextT(); // 先生成 Ha1

  for (let i = 0, len = msg.length; i < len; i++) {
    // t = Ha1 || Ha2 || Ha3 || Ha4
    if (offset === t.length) nextT();

    // c2 = msg ^ t
    msg[i] ^= t[offset++] & 0xff;
  }

  // c3 = hash(x2 || msg || y2)
  const checkC3 = _.arrayToHex(sm3$1([].concat(x2, msg, y2)));

  if (checkC3 === c3.toLowerCase()) {
    return output === 'array' ? msg : _.arrayToUtf8(msg)
  } else {
    return output === 'array' ? [] : ''
  }
}

/**
 * 签名
 */
function doSignature(msg, privateKey, {
  pointPool, der, hash, publicKey, userId
} = {}) {
  let hashHex = typeof msg === 'string' ? _.utf8ToHex(msg) : _.arrayToHex(msg);

  if (hash) {
    // sm3杂凑
    publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey);
    hashHex = getHash(hashHex, publicKey, userId);
  }

  const dA = new BigInteger(privateKey, 16);
  const e = new BigInteger(hashHex, 16);

  // k
  let k = null;
  let r = null;
  let s = null;

  do {
    do {
      let point;
      if (pointPool && pointPool.length) {
        point = pointPool.pop();
      } else {
        point = getPoint();
      }
      k = point.k;

      // r = (e + x1) mod n
      r = e.add(point.x1).mod(n);
    } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n))

    // s = ((1 + dA)^-1 * (k - r * dA)) mod n
    s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n);
  } while (s.equals(BigInteger.ZERO))

  if (der) return encodeDer(r, s) // asn.1 der 编码

  return _.leftPad(r.toString(16), 64) + _.leftPad(s.toString(16), 64)
}

/**
 * 验签
 */
function doVerifySignature(msg, signHex, publicKey, {der, hash, userId} = {}) {
  let hashHex = typeof msg === 'string' ? _.utf8ToHex(msg) : _.arrayToHex(msg);

  if (hash) {
    // sm3杂凑
    hashHex = getHash(hashHex, publicKey, userId);
  }

  let r; let
    s;
  if (der) {
    const decodeDerObj = decodeDer(signHex); // asn.1 der 解码
    r = decodeDerObj.r;
    s = decodeDerObj.s;
  } else {
    r = new BigInteger(signHex.substring(0, 64), 16);
    s = new BigInteger(signHex.substring(64), 16);
  }

  const PA = curve.decodePointHex(publicKey);
  const e = new BigInteger(hashHex, 16);

  // t = (r + s) mod n
  const t = r.add(s).mod(n);

  if (t.equals(BigInteger.ZERO)) return false

  // x1y1 = s * G + t * PA
  const x1y1 = G.multiply(s).add(PA.multiply(t));

  // R = (e + x1) mod n
  const R = e.add(x1y1.getX().toBigInteger()).mod(n);

  return r.equals(R)
}

/**
 * sm3杂凑算法
 */
function getHash(hashHex, publicKey, userId = '1234567812345678') {
  // z = hash(entl || userId || a || b || gx || gy || px || py)
  userId = _.utf8ToHex(userId);
  const a = _.leftPad(G.curve.a.toBigInteger().toRadix(16), 64);
  const b = _.leftPad(G.curve.b.toBigInteger().toRadix(16), 64);
  const gx = _.leftPad(G.getX().toBigInteger().toRadix(16), 64);
  const gy = _.leftPad(G.getY().toBigInteger().toRadix(16), 64);
  let px;
  let py;
  if (publicKey.length === 128) {
    px = publicKey.substr(0, 64);
    py = publicKey.substr(64, 64);
  } else {
    const point = G.curve.decodePointHex(publicKey);
    px = _.leftPad(point.getX().toBigInteger().toRadix(16), 64);
    py = _.leftPad(point.getY().toBigInteger().toRadix(16), 64);
  }
  const data = _.hexToArray(userId + a + b + gx + gy + px + py);

  const entl = userId.length * 4;
  data.unshift(entl & 0x00ff);
  data.unshift(entl >> 8 & 0x00ff);

  const z = sm3$1(data);

  // e = hash(z || msg)
  return _.arrayToHex(sm3$1(z.concat(_.hexToArray(hashHex))))
}

/**
 * 计算公钥
 */
function getPublicKeyFromPrivateKey(privateKey) {
  const PA = G.multiply(new BigInteger(privateKey, 16));
  const x = _.leftPad(PA.getX().toBigInteger().toString(16), 64);
  const y = _.leftPad(PA.getY().toBigInteger().toString(16), 64);
  return '04' + x + y
}

/**
 * 获取椭圆曲线点
 */
function getPoint() {
  const keypair = _.generateKeyPairHex();
  const PA = curve.decodePointHex(keypair.publicKey);

  keypair.k = new BigInteger(keypair.privateKey, 16);
  keypair.x1 = PA.getX().toBigInteger();

  return keypair
}

var sm2 = {
  generateKeyPairHex: _.generateKeyPairHex,
  compressPublicKeyHex: _.compressPublicKeyHex,
  comparePublicKeyHex: _.comparePublicKeyHex,
  doEncrypt,
  doDecrypt,
  doSignature,
  doVerifySignature,
  getPublicKeyFromPrivateKey,
  getPoint,
  verifyPublicKey: _.verifyPublicKey,
};

const {sm3, hmac} = sm3_1$1;

/**
 * 补全16进制字符串
 */
function leftPad(input, num) {
  if (input.length >= num) return input

  return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 字节数组转 16 进制串
 */
function ArrayToHex$1(arr) {
  return arr.map(item => {
    item = item.toString(16);
    return item.length === 1 ? '0' + item : item
  }).join('')
}

/**
 * 转成字节数组
 */
function hexToArray$1(hexStr) {
  const words = [];
  let hexStrLength = hexStr.length;

  if (hexStrLength % 2 !== 0) {
    hexStr = leftPad(hexStr, hexStrLength + 1);
  }

  hexStrLength = hexStr.length;

  for (let i = 0; i < hexStrLength; i += 2) {
    words.push(parseInt(hexStr.substr(i, 2), 16));
  }
  return words
}

/**
 * utf8 串转字节数组
 */
function utf8ToArray$1(str) {
  const arr = [];

  for (let i = 0, len = str.length; i < len; i++) {
    const point = str.codePointAt(i);

    if (point <= 0x007f) {
      // 单字节，标量值：00000000 00000000 0zzzzzzz
      arr.push(point);
    } else if (point <= 0x07ff) {
      // 双字节，标量值：00000000 00000yyy yyzzzzzz
      arr.push(0xc0 | (point >>> 6)); // 110yyyyy（0xc0-0xdf）
      arr.push(0x80 | (point & 0x3f)); // 10zzzzzz（0x80-0xbf）
    } else if (point <= 0xD7FF || (point >= 0xE000 && point <= 0xFFFF)) {
      // 三字节：标量值：00000000 xxxxyyyy yyzzzzzz
      arr.push(0xe0 | (point >>> 12)); // 1110xxxx（0xe0-0xef）
      arr.push(0x80 | ((point >>> 6) & 0x3f)); // 10yyyyyy（0x80-0xbf）
      arr.push(0x80 | (point & 0x3f)); // 10zzzzzz（0x80-0xbf）
    } else if (point >= 0x010000 && point <= 0x10FFFF) {
      // 四字节：标量值：000wwwxx xxxxyyyy yyzzzzzz
      i++;
      arr.push((0xf0 | (point >>> 18) & 0x1c)); // 11110www（0xf0-0xf7）
      arr.push((0x80 | ((point >>> 12) & 0x3f))); // 10xxxxxx（0x80-0xbf）
      arr.push((0x80 | ((point >>> 6) & 0x3f))); // 10yyyyyy（0x80-0xbf）
      arr.push((0x80 | (point & 0x3f))); // 10zzzzzz（0x80-0xbf）
    } else {
      // 五、六字节，暂时不支持
      arr.push(point);
      throw new Error('input is not supported')
    }
  }

  return arr
}

var sm3_1 = function (input, options) {
  input = typeof input === 'string' ? utf8ToArray$1(input) : Array.prototype.slice.call(input);

  if (options) {
    const mode = options.mode || 'hmac';
    if (mode !== 'hmac') throw new Error('invalid mode')

    let key = options.key;
    if (!key) throw new Error('invalid key')

    key = typeof key === 'string' ? hexToArray$1(key) : Array.prototype.slice.call(key);
    return ArrayToHex$1(hmac(input, key))
  }

  return ArrayToHex$1(sm3(input))
};

/* eslint-disable no-bitwise, no-mixed-operators, complexity */

const DECRYPT = 0;
const ROUND = 32;
const BLOCK = 16;

const Sbox = [
  0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
  0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
  0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
  0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
  0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
  0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
  0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
  0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
  0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
  0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
  0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
  0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
  0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
  0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
  0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
  0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
];

const CK = [
  0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
  0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
  0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
  0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
  0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
  0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
  0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
  0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
];

/**
 * 16 进制串转字节数组
 */
function hexToArray(str) {
  const arr = [];
  for (let i = 0, len = str.length; i < len; i += 2) {
    arr.push(parseInt(str.substr(i, 2), 16));
  }
  return arr
}

/**
 * 字节数组转 16 进制串
 */
function ArrayToHex(arr) {
  return arr.map(item => {
    item = item.toString(16);
    return item.length === 1 ? '0' + item : item
  }).join('')
}

/**
 * utf8 串转字节数组
 */
function utf8ToArray(str) {
  const arr = [];

  for (let i = 0, len = str.length; i < len; i++) {
    const point = str.codePointAt(i);

    if (point <= 0x007f) {
      // 单字节，标量值：00000000 00000000 0zzzzzzz
      arr.push(point);
    } else if (point <= 0x07ff) {
      // 双字节，标量值：00000000 00000yyy yyzzzzzz
      arr.push(0xc0 | (point >>> 6)); // 110yyyyy（0xc0-0xdf）
      arr.push(0x80 | (point & 0x3f)); // 10zzzzzz（0x80-0xbf）
    } else if (point <= 0xD7FF || (point >= 0xE000 && point <= 0xFFFF)) {
      // 三字节：标量值：00000000 xxxxyyyy yyzzzzzz
      arr.push(0xe0 | (point >>> 12)); // 1110xxxx（0xe0-0xef）
      arr.push(0x80 | ((point >>> 6) & 0x3f)); // 10yyyyyy（0x80-0xbf）
      arr.push(0x80 | (point & 0x3f)); // 10zzzzzz（0x80-0xbf）
    } else if (point >= 0x010000 && point <= 0x10FFFF) {
      // 四字节：标量值：000wwwxx xxxxyyyy yyzzzzzz
      i++;
      arr.push((0xf0 | (point >>> 18) & 0x1c)); // 11110www（0xf0-0xf7）
      arr.push((0x80 | ((point >>> 12) & 0x3f))); // 10xxxxxx（0x80-0xbf）
      arr.push((0x80 | ((point >>> 6) & 0x3f))); // 10yyyyyy（0x80-0xbf）
      arr.push((0x80 | (point & 0x3f))); // 10zzzzzz（0x80-0xbf）
    } else {
      // 五、六字节，暂时不支持
      arr.push(point);
      throw new Error('input is not supported')
    }
  }

  return arr
}

/**
 * 字节数组转 utf8 串
 */
function arrayToUtf8(arr) {
  const str = [];
  for (let i = 0, len = arr.length; i < len; i++) {
    if (arr[i] >= 0xf0 && arr[i] <= 0xf7) {
      // 四字节
      str.push(String.fromCodePoint(((arr[i] & 0x07) << 18) + ((arr[i + 1] & 0x3f) << 12) + ((arr[i + 2] & 0x3f) << 6) + (arr[i + 3] & 0x3f)));
      i += 3;
    } else if (arr[i] >= 0xe0 && arr[i] <= 0xef) {
      // 三字节
      str.push(String.fromCodePoint(((arr[i] & 0x0f) << 12) + ((arr[i + 1] & 0x3f) << 6) + (arr[i + 2] & 0x3f)));
      i += 2;
    } else if (arr[i] >= 0xc0 && arr[i] <= 0xdf) {
      // 双字节
      str.push(String.fromCodePoint(((arr[i] & 0x1f) << 6) + (arr[i + 1] & 0x3f)));
      i++;
    } else {
      // 单字节
      str.push(String.fromCodePoint(arr[i]));
    }
  }

  return str.join('')
}

/**
 * 32 比特循环左移
 */
function rotl(x, n) {
  const s = n & 31;
  return (x << s) | (x >>> (32 - s))
}

/**
 * 非线性变换
 */
function byteSub(a) {
  return (Sbox[a >>> 24 & 0xFF] & 0xFF) << 24 |
    (Sbox[a >>> 16 & 0xFF] & 0xFF) << 16 |
    (Sbox[a >>> 8 & 0xFF] & 0xFF) << 8 |
    (Sbox[a & 0xFF] & 0xFF)
}

/**
 * 线性变换，加密/解密用
 */
function l1(b) {
  return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

/**
 * 线性变换，生成轮密钥用
 */
function l2(b) {
  return b ^ rotl(b, 13) ^ rotl(b, 23)
}

/**
 * 以一组 128 比特进行加密/解密操作
 */
function sms4Crypt(input, output, roundKey) {
  const x = new Array(4);

  // 字节数组转成字数组（此处 1 字 = 32 比特）
  const tmp = new Array(4);
  for (let i = 0; i < 4; i++) {
    tmp[0] = input[4 * i] & 0xff;
    tmp[1] = input[4 * i + 1] & 0xff;
    tmp[2] = input[4 * i + 2] & 0xff;
    tmp[3] = input[4 * i + 3] & 0xff;
    x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
  }

  // x[i + 4] = x[i] ^ l1(byteSub(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ roundKey[i]))
  for (let r = 0, mid; r < 32; r += 4) {
    mid = x[1] ^ x[2] ^ x[3] ^ roundKey[r + 0];
    x[0] ^= l1(byteSub(mid)); // x[4]

    mid = x[2] ^ x[3] ^ x[0] ^ roundKey[r + 1];
    x[1] ^= l1(byteSub(mid)); // x[5]

    mid = x[3] ^ x[0] ^ x[1] ^ roundKey[r + 2];
    x[2] ^= l1(byteSub(mid)); // x[6]

    mid = x[0] ^ x[1] ^ x[2] ^ roundKey[r + 3];
    x[3] ^= l1(byteSub(mid)); // x[7]
  }

  // 反序变换
  for (let j = 0; j < 16; j += 4) {
    output[j] = x[3 - j / 4] >>> 24 & 0xff;
    output[j + 1] = x[3 - j / 4] >>> 16 & 0xff;
    output[j + 2] = x[3 - j / 4] >>> 8 & 0xff;
    output[j + 3] = x[3 - j / 4] & 0xff;
  }
}

/**
 * 密钥扩展算法
 */
function sms4KeyExt(key, roundKey, cryptFlag) {
  const x = new Array(4);

  // 字节数组转成字数组（此处 1 字 = 32 比特）
  const tmp = new Array(4);
  for (let i = 0; i < 4; i++) {
    tmp[0] = key[0 + 4 * i] & 0xff;
    tmp[1] = key[1 + 4 * i] & 0xff;
    tmp[2] = key[2 + 4 * i] & 0xff;
    tmp[3] = key[3 + 4 * i] & 0xff;
    x[i] = tmp[0] << 24 | tmp[1] << 16 | tmp[2] << 8 | tmp[3];
  }

  // 与系统参数做异或
  x[0] ^= 0xa3b1bac6;
  x[1] ^= 0x56aa3350;
  x[2] ^= 0x677d9197;
  x[3] ^= 0xb27022dc;

  // roundKey[i] = x[i + 4] = x[i] ^ l2(byteSub(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ CK[i]))
  for (let r = 0, mid; r < 32; r += 4) {
    mid = x[1] ^ x[2] ^ x[3] ^ CK[r + 0];
    roundKey[r + 0] = x[0] ^= l2(byteSub(mid)); // x[4]

    mid = x[2] ^ x[3] ^ x[0] ^ CK[r + 1];
    roundKey[r + 1] = x[1] ^= l2(byteSub(mid)); // x[5]

    mid = x[3] ^ x[0] ^ x[1] ^ CK[r + 2];
    roundKey[r + 2] = x[2] ^= l2(byteSub(mid)); // x[6]

    mid = x[0] ^ x[1] ^ x[2] ^ CK[r + 3];
    roundKey[r + 3] = x[3] ^= l2(byteSub(mid)); // x[7]
  }

  // 解密时使用反序的轮密钥
  if (cryptFlag === DECRYPT) {
    for (let r = 0, mid; r < 16; r++) {
      mid = roundKey[r];
      roundKey[r] = roundKey[31 - r];
      roundKey[31 - r] = mid;
    }
  }
}

function sm4(inArray, key, cryptFlag, {
  padding = 'pkcs#7', mode, iv = [], output = 'string'
} = {}) {
  if (mode === 'cbc') {
    // CBC 模式，默认走 ECB 模式
    if (typeof iv === 'string') iv = hexToArray(iv);
    if (iv.length !== (128 / 8)) {
      // iv 不是 128 比特
      throw new Error('iv is invalid')
    }
  }

  // 检查 key
  if (typeof key === 'string') key = hexToArray(key);
  if (key.length !== (128 / 8)) {
    // key 不是 128 比特
    throw new Error('key is invalid')
  }

  // 检查输入
  if (typeof inArray === 'string') {
    if (cryptFlag !== DECRYPT) {
      // 加密，输入为 utf8 串
      inArray = utf8ToArray(inArray);
    } else {
      // 解密，输入为 16 进制串
      inArray = hexToArray(inArray);
    }
  } else {
    inArray = [...inArray];
  }

  // 新增填充，sm4 是 16 个字节一个分组，所以统一走到 pkcs#7
  if ((padding === 'pkcs#5' || padding === 'pkcs#7') && cryptFlag !== DECRYPT) {
    const paddingCount = BLOCK - inArray.length % BLOCK;
    for (let i = 0; i < paddingCount; i++) inArray.push(paddingCount);
  }

  // 生成轮密钥
  const roundKey = new Array(ROUND);
  sms4KeyExt(key, roundKey, cryptFlag);

  const outArray = [];
  let lastVector = iv;
  let restLen = inArray.length;
  let point = 0;
  while (restLen >= BLOCK) {
    const input = inArray.slice(point, point + 16);
    const output = new Array(16);

    if (mode === 'cbc') {
      for (let i = 0; i < BLOCK; i++) {
        if (cryptFlag !== DECRYPT) {
          // 加密过程在组加密前进行异或
          input[i] ^= lastVector[i];
        }
      }
    }

    sms4Crypt(input, output, roundKey);


    for (let i = 0; i < BLOCK; i++) {
      if (mode === 'cbc') {
        if (cryptFlag === DECRYPT) {
          // 解密过程在组解密后进行异或
          output[i] ^= lastVector[i];
        }
      }

      outArray[point + i] = output[i];
    }

    if (mode === 'cbc') {
      if (cryptFlag !== DECRYPT) {
        // 使用上一次输出作为加密向量
        lastVector = output;
      } else {
        // 使用上一次输入作为解密向量
        lastVector = input;
      }
    }

    restLen -= BLOCK;
    point += BLOCK;
  }

  // 去除填充，sm4 是 16 个字节一个分组，所以统一走到 pkcs#7
  if ((padding === 'pkcs#5' || padding === 'pkcs#7') && cryptFlag === DECRYPT) {
    const len = outArray.length;
    const paddingCount = outArray[len - 1];
    for (let i = 1; i <= paddingCount; i++) {
      if (outArray[len - i] !== paddingCount) throw new Error('padding is invalid')
    }
    outArray.splice(len - paddingCount, paddingCount);
  }

  // 调整输出
  if (output !== 'array') {
    if (cryptFlag !== DECRYPT) {
      // 加密，输出转 16 进制串
      return ArrayToHex(outArray)
    } else {
      // 解密，输出转 utf8 串
      return arrayToUtf8(outArray)
    }
  } else {
    return outArray
  }
}

var sm4_1 = {
  encrypt(inArray, key, options) {
    return sm4(inArray, key, 1, options)
  },
  decrypt(inArray, key, options) {
    return sm4(inArray, key, 0, options)
  }
};

var src = {
  sm2: sm2,
  sm3: sm3_1,
  sm4: sm4_1,
};

// 随机密钥生成，【用于对称加密】
/**
 * 获取随机数
 * @param {number} len 随机数长度
 * @param {string} mode 随机数模式 high:高级 medium:中等 low:低等
 */
const randomPassword = (len = 16, mode = 'high') => {
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
    ];
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
    ];
    const numberArr = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
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
    ];
    const passArr = [];
    let password = '';
    //指定参数随机获取一个字符
    const specifyRandom = function (...arr) {
        let str = '';
        arr.forEach((item) => {
            str += item[Math.floor(Math.random() * item.length)];
        });
        return str;
    };
    switch (mode) {
        case 'high':
            //安全最高的
            password += specifyRandom(lowerCaseArr, blockLetterArr, numberArr, specialArr);
            passArr.push(...lowerCaseArr, ...blockLetterArr, ...numberArr, ...specialArr);
            break;
        case 'medium':
            //中等的
            password += specifyRandom(lowerCaseArr, blockLetterArr, numberArr);
            passArr.push(...lowerCaseArr, ...blockLetterArr, ...numberArr);
            break;
        //低等的
        case 'low':
            password += specifyRandom(lowerCaseArr, numberArr);
            passArr.push(...lowerCaseArr, ...numberArr);
            break;
        default:
            password += specifyRandom(lowerCaseArr, numberArr);
            passArr.push(...lowerCaseArr, ...numberArr);
    }
    const forLen = len - password.length;
    for (let i = 0; i < forLen; i++) {
        password += specifyRandom(passArr);
    }
    return password;
};
const HEADER_ENCRYPT_KEY = 'X-Encrypt-Key';
const HEADER_ENCRYPT_WITH = 'X-Encrypt-With';
const setRequestCryptoHeader = (headers, encryptKey) => {
    headers.set(HEADER_ENCRYPT_KEY, encryptKey);
    return headers;
};
const isEncryptResponse = (headers) => {
    const headerValue = headers.get(HEADER_ENCRYPT_WITH);
    return (headerValue &&
        typeof headerValue === 'string' &&
        headerValue.toLowerCase() === 'sm4');
};
function ab2str(buf, encoding = 'utf-8') {
    const enc = new TextDecoder(encoding);
    return enc.decode(buf);
}
function transformResponseData(data) {
    if (typeof data === 'string') {
        try {
            data = JSON.parse(data);
        }
        catch (e) {
            console.error('error', e);
            throw e;
        }
    }
    if (data instanceof ArrayBuffer) {
        return ab2str(data);
    }
    return data;
}
function transformArrayBufferToJsonData(data) {
    try {
        if (data instanceof ArrayBuffer) {
            return transformStringToJsonData(ab2str(data));
        }
        return data;
    }
    catch (e) {
        console.error('error', e);
        throw e;
    }
}
function transformStringToJsonData(data) {
    try {
        if (typeof data === 'string') {
            return JSON.parse(data);
        }
        return data;
    }
    catch (e) {
        console.error('error', e);
        throw e;
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
const isEncryptListApi = (url) => {
    const reg = /^\/(api\/logmanage|api\/data-source|api\/enterpriseadmin|api\/componentmanager|api\/spacemanager|api\/filemanager)/;
    return reg.test(url);
};
// 不加密名单
// start with /bi-api/api
const encryptWhiteList = (url) => {
    const reg = /^\/bi-api\/api/;
    return reg.test(url);
};
//  接口加密规则
const shouldEncrypt = (url) => {
    // 默认全部加密
    let ret = true;
    if (encryptWhiteList(url)) {
        return false;
    }
    // api 开头默认不加密
    if (url.startsWith('/api')) {
        ret = false;
        // 如果在名单列表则加密
        if (isEncryptListApi(url)) {
            ret = true;
        }
    }
    return ret;
};

// 对称加密方法 information 生成
const getCryptoInfo = (algorithm) => {
    const psd = randomPassword(16, 'high');
    const info = {
        key: psd,
        algorithm: algorithm || 'SM4',
    };
    return {
        ...info,
    };
};
// 对称加密解密方法
// 非对称加密加密方法
// function asymmetricEncrypt(
//   data: string,
//   publicKey: string,
//   fn: (...args: any) => any,
// ) {
//
// }
// 非对称加密解密方法
const getSm4EncryptConfig = () => {
    return {
        mode: 'ecb',
        padding: 'pkcs#7',
        output: 'array',
    };
};

const Buffer = buffer.Buffer;
const sm4EncryptConfig = getSm4EncryptConfig();
const createEncryptFn = function (__store, asymmetricKey) {
    return (data, headers) => {
        try {
            if (headers.closeCrypto) {
                return data;
            }
            __store.info = getCryptoInfo();
            __store.publicKey = [...Buffer.from(__store.info.key)];
            const encryptInfo = src.sm2.doEncrypt(JSON.stringify(__store.info), asymmetricKey, 1);
            setRequestCryptoHeader(headers, encryptInfo);
            if (data) {
                if (typeof data !== 'string') {
                    data = JSON.stringify(data);
                }
                const array = src.sm4.encrypt(data, __store.publicKey, sm4EncryptConfig);
                data = Buffer.from(array);
                return data;
            }
            else {
                return data;
            }
        }
        catch (e) {
            console.error('encrypt error', e, data, headers);
        }
    };
};
const createDecryptFn = function (__store) {
    return (data, headers) => {
        try {
            if (isEncryptResponse(headers)) {
                const arrayData = Buffer.from(data);
                const decryptData = src.sm4.decrypt(arrayData, __store.publicKey, {
                    mode: 'ecb',
                    padding: 'pkcs#7',
                });
                return transformStringToJsonData(decryptData);
            }
            else {
                return transformArrayBufferToJsonData(data);
            }
        }
        catch (e) {
            console.error('decrypt error', e, data, headers);
        }
    };
};
function addEncryptFnToTransformRequest(instance, asymmetricKey) {
    if (!asymmetricKey || typeof asymmetricKey !== 'string') {
        throw new Error(`publicKey is required and must be a string ${asymmetricKey}`);
    }
    // 通过url过滤
    instance.interceptors.request.use((config) => {
        const url = config.url;
        const headers = config.headers;
        if (!url) {
            throw new Error('url is required');
        }
        if ({}.hasOwnProperty.call(headers, 'closeCrypto')) {
            return config;
        }
        const encrypt = shouldEncrypt(url);
        if (!encrypt) {
            console.log(`url: ${url} shouldCloseCrypto: ${!encrypt}`);
            headers.closeCrypto = true;
        }
        return config;
    });
    // 过滤formData类型数据
    instance.interceptors.request.use((config) => {
        const data = config.data;
        const headers = config.headers;
        if (!data) {
            return config;
        }
        if (data instanceof FormData) {
            console.log(`body of request: ${config.url} is FormData: ${data}`);
            headers.closeCrypto = true;
        }
        return config;
    });
    // 非过滤数据返回类型声明
    instance.interceptors.request.use((config) => {
        const headers = config.headers;
        if (!headers.closeCrypto) {
            config.responseType = 'arraybuffer';
        }
        return config;
    });
    // 加密，解密添加 数据
    instance.interceptors.request.use((value) => {
        const transformRequest = value.transformRequest;
        const __store = {
            info: null,
            publicKey: [],
        };
        if (!transformRequest) {
            throw new Error(`request ${value} has no transformRequest`);
        }
        if (Array.isArray(transformRequest)) {
            transformRequest.push(createEncryptFn(__store, asymmetricKey));
        }
        else {
            throw new Error(`transformRequest ${transformRequest} is not an array`);
        }
        const decryptFn = createDecryptFn(__store);
        if (!decryptFn) {
            return value;
        }
        const transformResponse = value.transformResponse;
        if (!transformResponse) {
            throw new Error(`request ${value} has no transformResponse`);
        }
        if (typeof decryptFn !== 'function') {
            throw new Error(`decryptFn ${decryptFn} is not a function`);
        }
        if (Array.isArray(transformResponse)) {
            transformResponse.unshift(decryptFn);
        }
        else {
            throw new Error(`transformResponse ${transformResponse} is not an array`);
        }
        return value;
    });
    // 返回数据转换
    instance.interceptors.response.use((data) => {
        data.data = transformArrayBufferToJsonData(data.data);
        data.data = transformStringToJsonData(data.data);
        return data;
    }, (error) => {
        const response = error.response;
        if (response?.data) {
            response.data = transformResponseData(response.data);
        }
        throw error;
    });
}
const createCryptoAxiosInstance = (options, asymmetricKey) => {
    const instance = axios.create(options);
    addEncryptFnToTransformRequest(instance, asymmetricKey);
    return instance;
};

export { createCryptoAxiosInstance, createRequestInstance, getCryptoInfo, getSm4EncryptConfig, randomPassword, shouldEncrypt };
