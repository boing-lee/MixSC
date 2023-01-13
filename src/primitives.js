const crypto = require("crypto");
const BN = require("bn.js");
const params = require("./params");
const { serialize } = require("./serialize");
const Web3 = require("web3");
const {CT, G1Point} = require("./types");

function toBN10(str) {
  return new BN(str, 10);
}

function commit(g, m, h, r) {
  return g.mul(m).add(h.mul(r));
}

function multiExponents(h, exp) {
  let tmp = params.zero;
  h.forEach((item, index) => {
    tmp = tmp.add(item.mul(exp[index]));
  });
  return tmp;
}

function commitBits(g, h, exp, r) {
  const tmp = multiExponents(h, exp);
  return g.mul(r).add(tmp);
}

function randomExponent() {
  return new BN(crypto.randomBytes(32)).mod(params.curve.n);
}

function randomGroupElement() {
  const seed_red = randomExponent().toRed(params.p);
  const p_1_4 = params.curve.p.add(new BN(1)).div(new BN(4));
  while (true) {
    const y_squared = seed_red
      .redPow(new BN(3))
      .redAdd(new BN(3).toRed(params.p));
    const y = y_squared.redPow(p_1_4);
    if (y.redPow(new BN(2)).eq(y_squared)) {
      return params.curve.point(seed_red.fromRed(), y.fromRed());
    }
    seed_red.redIAdd(new BN(1).toRed(params.p));
  }
}

function generateChallenge(group_elements) {
  const mapped_params = group_elements.map((elem) => {
    return serialize(elem);
  });

  const web3 = new Web3();
  const encoded = web3.eth.abi.encodeParameters(
    ["struct(bytes32,bytes32)[]"],
    [mapped_params]
  );
  const sha256 = crypto.createHash("sha256");
  sha256.update(Buffer.from(encoded.slice(2), "hex"));
  const hash_out = sha256.digest("hex");
  const result_out = new BN(hash_out, "hex");
  return result_out;
}

function convertToSigma(num, n, m) {
  const out = new Array();
  var j = 0;
  for (j = 0; j < m; j++) {
    const rem = num % n;
    num = Math.floor(num / n);
    for (let i = 0; i < n; i++) {
      out.push(i == rem ? new BN(1) : new BN(0));
    }
  }
  return out;
}

function convertToNal(num, n, m) {
  const out = new Array();
  var j = 0;
  while (num != 0) {
    const rem = num % n;
    num = Math.floor(num / n);
    out.push(rem);
    j++;
  }
  if (out.length > m) return out.slice(0, m);
  if (out.length < m)
    out.splice(out.length, 0, ...new Array(m - out.length).fill(0));
  return out;
}

function newFactor(x, a, coefficients) {
  const degree = coefficients.length;
  coefficients.push(x.mul(coefficients[degree - 1]));
  for (let d = degree - 1; d >= 1; d--) {
    coefficients[d] = a.mul(coefficients[d]).add(x.mul(coefficients[d - 1]));
  }
  coefficients[0] = coefficients[0].mul(a);
}


function TwistedElgamal(twElParams) {
  let cesc = new CT();
  cesc.XX = twElParams.pk.mul(twElParams.k);
  cesc.YY = twElParams.g.mul(twElParams.k).add(twElParams.h.mul(twElParams.v));
  return cesc;
}


function hashString2Int(str) {
  var hash = 0, i, chr;
  if (this.length === 0) return hash;
  for (i = 0; i < str.length; i++) {
    chr   = str.charCodeAt(i);
    hash  = ((hash << 5) - hash) + chr;
    hash |= 0; // Convert to 32bit integer
  }
  return new BN(Math.abs(hash)).mod(params.curve.n);
};


function getMi(l) {
  let i = 0;
  let base = 2;
  while(true) {
    if(l < Math.pow(base, i)) {
      return i;
    }
    i++;
  }
}


function geths(m, n, g) {
  let hs = new Array(m * n);
  for(let i = 0; i < m; i++) {
    hs[2*i] = g.mul(hashString2Int(String(i) + String(m)));
    hs[2*i+1] = g.mul(hashString2Int(String(m) + String(i)));
  }
  return hs;
}

function getDelta(l_bin, m) {
  let delta = new Array(2*m);
  for(let i = 0; i < m; i++) {
    if(l_bin[i] == 0) {
      delta[2*i]=1;
      delta[2*i+1]=0;
    }else {
      delta[2*i] = 0;
      delta[2*i+1] = 1;
    }
  }
  return delta;
}


function TwoPolyMul(s1, index1, s2, index2) {
  let tmp = new Array(index1+1);
  for(let i = 0; i < index1+1; i++) {
    tmp[i] = new BN(0);
  }
  let index = index1;
  for(let i = 0; i < index2; i++) {
    for(let j = 0; j < index1; j++) {
      tmp[i+j]=s1[j].mul(s2[i]).add(tmp[i+j]);
      if(i+j+1>index1) index = i+j+1;
    }
  }
  return [tmp, index];
}

//s为BN
function PolyMul(m,s) {
  let s1 = new Array(m+1);
  let s2 = new Array(2);
  let index = 2;
  let k = 1;
  s1[0] = s[0];
  s1[1] = s[1];
  while(k < m) {
    s2[0] = s[2*k];
    s2[1] = s[2*k+1];
    [s1, index] = TwoPolyMul(s1, index, s2, 2);
    k++;
  }
  return s1;
}


  //delta为number,a_m为BN
  function getP(i, delta, a_m, m) {
    let i_bin = convertToNal(i, 2, m);
    let s = new Array(2*m);
    for(let j = 0; j < m; j++) {
      s[2*j] = a_m[j*2 + i_bin[j]];
      s[2*j+1] = new BN(delta[j*2+i_bin[j]]);
    }
    return PolyMul(m, s);
  }

//导出使用
function GetP(l, i, m, a) {
  return getP(i, getDelta(convertToNal(l,2,m),m), a, m);


}



module.exports = {
  toBN10,
  commit,
  multiExponents,
  commitBits,
  randomExponent,
  randomGroupElement,
  generateChallenge,
  newFactor,
  convertToNal,
  convertToSigma,
  TwistedElgamal,
  hashString2Int,
  getMi,
  geths,
  getDelta,
  GetP,
};
