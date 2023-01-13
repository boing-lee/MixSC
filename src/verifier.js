const BN = require("bn.js");
const { zero, p, q, curve, g, h} = require("./params");
const {
  commit,
  commitBits,
  convertToNal,
  generateChallenge,
  multiExponents,
  hashString2Int,
  TwistedElgamal,
} = require("./primitives");
const { serialize, toBytes } = require("./serialize");
const { RedeemStatement, CT, R1Auxiliaries, TwistedElgamalParams } = require("./types");


function verifyProofEscrow(proofEscrow) {
  if(!verifyToken(proofEscrow.token,proofEscrow.R,proofEscrow.GBase, proofEscrow.z)) return false;

  return true;
}


function verifyToken(token, R, GBase, z) {
  var c = hashString2Int(JSON.stringify(token) + JSON.stringify(R));
  let g1 = GBase.mul(z);
  let g2 = token.mul(c).add(R);
  if(g1.eq(g2)) {
    return true;
  } else {
    return false;
  }

}


function verifyRedeemProofFormat(proofFormat, auxFormat,input, esc_pool) {
  let clist1 = new Array(esc_pool.length);
  let clist2 = new Array(esc_pool.length);
  if(!verifyFormat(input.cred, input)) return false;
  for(let i = 0; i < esc_pool.length; i++) {
    clist1[i] = input.cred.XX.add(esc_pool[i].cesc.XX.add(esc_pool[i].mu.neg()));
    clist2[i] = input.cred.YY.add(esc_pool[i].cesc.YY.neg());
  }
  if(!verifySigmaProof(clist1, clist2, proofFormat, auxFormat,input.pk)) return false;

  return true;

}


function verifyFormat(cred, input) {
  let e = hashString2Int(JSON.stringify(input.A) + JSON.stringify(input.B));
  let tmp = input.pk.mul(input.z1);
  let actual = cred.XX.mul(e).add(input.A);

  if(!tmp.eq(actual)) {
    return false;
  }
  tmp = g.mul(input.z1).add(h.mul(input.z2));
  actual = input.B.add(cred.YY.mul(e));
  if(!tmp.eq(actual)) {
    return false;
  }
  return true;
}

function verifySigmaProof(commits1, commits2, proof, aux, pk) {
  let N = commits1.length;
  let f = new Array(aux.n * aux.m);
  let r1aux = new R1Auxiliaries();
  r1aux.n = aux.n;
  r1aux.m = aux.m;
  r1aux.B_commit = proof.B;
  r1aux.g = aux.g;
  r1aux.h = r1aux.h;
  r1aux.g_new = aux.g_new;
  r1aux.hs = aux.hs;
  if(!verifyR1Proof(proof.r1Proof, r1aux, true)) return false;
  let group_elements = new Array(proof.Gk1.length + proof.Gk2.length + 4);
  group_elements[0] = proof.r1Proof.A;
  group_elements[1] = proof.B;
  group_elements[2] = proof.r1Proof.C;
  group_elements[3] = proof.r1Proof.D;
  for(let i = 0; i < proof.Gk1.length; i++) {
    group_elements[i + 4] = proof.Gk1[i];
  }
  for(let i = 0; i < proof.Gk2.length; i++) {
    group_elements[proof.Gk1.length + i + 4] = proof.Gk2[i];
  }
  let challenge_x = generateChallenge(group_elements);//TODO

  if(!verifyR1Final(proof.r1Proof, r1aux, challenge_x, f)) return false;//TODO
  //生成f_i_
  let f_i_ = new Array(N);
  let I;
  for(let i = 0; i < N; i++) {
    I = convertToNal(i, aux.n, aux.m);
    let f_i = new BN(1);
    for(let j = 0; j < aux.m; j++) {
      f_i = f_i.mul(f[j * aux.n + I[j]]);
    }
    f_i_[i] = f_i;
  }

  let left = new Array(2);
  [left[0], left[1]] = GenerateSigmaProofLeft(commits1, commits2, aux, f_i_, proof, challenge_x);//TODO
  let twElParams = new TwistedElgamalParams();
  twElParams.g = aux.g;
  twElParams.h = aux.h;
  twElParams.k = proof.z;
  twElParams.v = new BN(0);
  twElParams.pk = pk;

  let cmp = TwistedElgamal(twElParams);

  if(!left[1].eq(cmp.YY)) {
    console.log("127 is bad!");
  }

  if ( !(left[1].eq(cmp.YY))) return false;

  return true;
}



function verifyR1Proof(proof, aux, skip_final) {
  if(!skip_final) {
    let group_elements = new Array(4);
    group_elements[0] = proof.A;
    group_elements[1] = aux.B_commit;
    group_elements[2] = proof.C;
    group_elements[3] = proof.D;
    let challenge_x = generateChallenge(group_elements);
    return verifyR1Final(proof, aux, challenge_x, f_out);
  }
  return true;

}


function verifyR1Final(proof, aux, challenge_x, f_out) {
  //console.log(proof.f);
  //console.log(proof.f.length);

  for(let j = 0; j < proof.f.length; j++) {
    if(j % aux.n == 0) continue;
    //console.log("j",j, proof.f[j]);
    if(challenge_x.eq(proof.f[j])) return false; //TODO
  }
  for(let j = 0; j < aux.m; j++) {
    let tmp = new BN(0);
    for(let i = 1; i < aux.n; i++) {
      tmp = tmp.add(proof.f[j*aux.n + i]);
      f_out[j*aux.n+i] = proof.f[j*aux.n + i];
    }
    f_out[j*aux.n] = challenge_x.sub(tmp);
  }
  let one = commitBits(aux.g_new, aux.hs, f_out, proof.zA);
  let cmp = aux.B_commit.mul(challenge_x).add(proof.A);
  if(!one.eq(cmp)) return false;

  let f_outprime = new Array(f_out.length);
  for(let i = 0; i < f_out.length; i++) {
    f_outprime[i] = f_out[i].mul(challenge_x.sub(f_out[i]));
  }
  let two = commitBits(aux.g_new, aux.hs, f_outprime, proof.zC);
  cmp = proof.C.mul(challenge_x).add(proof.D);
  if(!two.eq(cmp)) return false;
  return true;
}



function GenerateSigmaProofLeft(commits1, commits2, aux, f_i_, proof, challenge_x) {
  let left1;
  let t1 = multiExponents(commits1, f_i_);
  let t2 = zero;
  for(let k = 0; k < aux.m; k++) {
    t2 = t2.add(proof.Gk1[k].mul(challenge_x.pow(new BN(k)).neg() ));
  }

  left1 = t1.add(t2);

  let left2;
  let t3 = multiExponents(commits2, f_i_)
  let t4 = zero;
  for(let k = 0; k < aux.m; k++) {
    t4 = t4.add(proof.Gk2[k].mul(challenge_x.pow(new BN(k)).neg() ) ); //TODO
  }
  left2 = t3.add(t4);

  return [left1, left2];

}






class R1Verifier {
  constructor(g, h, B, n, m) {
    this.g = g;
    this.h = h;
    this.B_commit = B;
    this.n = n;
    this.m = m;
  }

  verify(proof, skip_final_response = false) {
    const f = new Array();
    return this._verify(proof, f, skip_final_response);
  }

  _verify(proof, f_out, skip_final_response) {
    if (
      proof.A.isInfinity() ||
      proof.C.isInfinity() ||
      proof.D.isInfinity() ||
      this.B_commit.isInfinity()
    )
      return false;
    for (let i = 0; i < proof.f.length; i++) {
      if (proof.f[i].isZero()) return false;
    }
    if (proof.ZA.isZero() || proof.ZC.isZero()) return false;
    if (!skip_final_response) {
      const group_elements = [proof.A, this.B_commit, proof.C, proof.D];
      const x = generateChallenge(group_elements);
      return this.verify_final_response(proof, x, f_out);
    }
    return true;
  }

  verify_final_response(proof, challenge_x, f_out) {
    const f = proof.f;
    for (let j = 0; j < f.length; ++j) {
      if (f[j].eq(challenge_x)) return false;
    }

    f_out.splice(0);
    for (let j = 0; j < this.m; j++) {
      f_out.push(new BN(0));
      let tmp = new BN(0);
      const k = this.n - 1;
      for (let i = 0; i < k; i++) {
        tmp = tmp.add(f[j * k + i]);
        f_out.push(f[j * k + i]);
      }
      f_out[j * this.n] = challenge_x.sub(tmp).add(curve.n).mod(curve.n);
    }

    const one = commitBits(this.g, this.h, f_out, proof.ZA);

    if (!one.eq(this.B_commit.mul(challenge_x).add(proof.A))) {
      return false;
    }

    const f_outprime = new Array(f_out.length);
    for (let i = 0; i < f_out.length; i++) {
      const exp = challenge_x.sub(f_out[i]).add(curve.n).mod(curve.n);
      f_outprime[i] = f_out[i].mul(exp).mod(curve.n);
    }

    const two = commitBits(this.g, this.h, f_outprime, proof.ZC);
    if (!two.eq(proof.C.mul(challenge_x).add(proof.D))) {
      return false;
    }

    return true;
  }
}

class SigmaVerifier {
  constructor(g, h_gens, n, m) {
    this.g = g;
    this.h = h_gens;
    this.n = n;
    this.m = m;
  }

  verify(commits, proof) {
    const r1verifier = new R1Verifier(this.g, this.h, proof.B, this.n, this.m);
    const r1proof = proof.r1Proof;
    if (!r1verifier.verify(r1proof, true)) return false;

    if (proof.B.isInfinity()) return false;

    const Gk = proof.Gk;
    for (let i = 0; i < Gk.length; i++) {
      if (Gk[i].isInfinity()) return false;
    }

    const group_elements = new Array(r1proof.A, proof.B, r1proof.C, r1proof.D);
    group_elements.splice(group_elements.length, 0, ...Gk);
    const challenge_x = generateChallenge(group_elements);
    const f = new Array();
    if (!r1verifier.verify_final_response(r1proof, challenge_x, f))
      return false;

    if (proof.z.isZero()) return false;
    if (commits.length == 0) return false;

    const N = commits.length;
    const f_i_ = new Array(N);
    for (let i = 0; i < N; i++) {
      const I = convertToNal(i, this.n, this.m);
      let f_i = new BN(1);
      for (let j = 0; j < this.m; j++) {
        f_i = f_i.mul(f[j * this.n + I[j]]).mod(curve.n);
      }
      f_i_[i] = f_i;
    }

    const t1 = multiExponents(commits, f_i_);

    let t2 = zero;
    let x_k = new BN(1);
    for (let k = 0; k < this.m; k++) {
      t2 = t2.add(Gk[k].mul(x_k.neg()));
      x_k = x_k.mul(challenge_x);
    }

    const left = t1.add(t2);
    const cmp = commit(this.g, new BN(0), this.h[0], proof.z);

    if (!left.eq(cmp)) {
      return false;
    }
    return true;
  }
}

module.exports = { R1Verifier, SigmaVerifier,verifyProofEscrow,verifyRedeemProofFormat };
