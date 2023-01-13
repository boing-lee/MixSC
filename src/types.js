const BN = require("bn.js");
const { zero } = require("./params");

//定义结构体define struct
class R1Proof {
  constructor() {
    this.A = zero;
    this.C = zero;
    this.D = zero;
    this.f = [];
    this.ZA = new BN(0);
    this.ZC = new BN(0);
  }
}

class SigmaProof {
  constructor() {
    this.n = 0;
    this.m = 0;
    this.B = zero;
    this.r1Proof = new R1Proof();
    this.Gk = [];
    this.z = new BN(0);
  }
}

class ProofEscrow {
  constructor() {
    this.pk;
    this.tokenKind;
    this.token;
    this.mu;
    this.R;
    this.GBase;
    this.z;
    this.c;
  }

}


class TwistedElgamalParams {
  constructor() {
    this.g;
    this.h;
    this.k;
    this.v;
    this.pk;
  }

}

class EscrowStatement {
  constructor() {
    this.cesc;
    this.token;
    this.mu;
  }

}

class RedeemStatement {
  constructor() {
    this.cred = new CT();
  }

}

class R1Auxiliaries {
  constructor() {
    this.n;
    this.m;
    this.B_commit;
    this.g;//setUp中的Tw加密原始   ek
    this.h;
    this.g_new;//用于commitBits   ck
    this.hs;
  }
}


class AuxRedeem1 {
  constructor() {
    this.r;//BN
    this.a;//BN
    this.b;//BN
    this.l;//number
    this.m;//number
    this.n;//number
    this.tmpCesc = new CT();
    this.cesc = new CT();//CT
    this.mu;//BN
    this.f_base;//BN
    this.token;//BN
    this.tmpCred;//CT
  }
}

class AuxRedeem2 {
  constructor() {
    this.N;//number
    this.clist1;
    this.clist2;
    this.rB;
    this.rouk;
    this.newG_ck;
    this.hs;
    this.delta;//[] number
    this.Gk1 = [];
    this.Gk2 = [];
    this.a;
  }
}

class RequestRedeemInput {
  constructor() {
    this.k;
    this.td;
    this.v;
    this.pkr;
    this.randomString;
  }
}

class AuxprocessRedeem {
  constructor() {
    this.A;
    this.B;
    this.C;
    this.D;
    this.f;
    this.zA;
    this.zC;
    this.z;
    this.tmpz;
  }
}


class RedeemProofStep2 {
  constructor() {
    this.A;
    this.B;
    this.z1;
    this.z2;
  }
}

class AuxR1ProofPart1Input {
  constructor() {
    this.g; //Point
    this.hs;//Point
    this.B;//Point
    this.b;
    this.r;
    this.m;//number
    this.n;//number
    this.a;//随机数矩阵a
  }
}
// struct AuxR1ProofPart2Input {
//   uint256 m;
//   uint256 n;
//   uint256 challenge_x;
//   uint256[] a;
//   uint256[] b;
//   uint256 r;
//   uint256[3] rArCrD;
// }


class AuxR1ProofPart2Input {
  constructor() {
    this.m;
    this.n;
    this.challenge_x;
    this.a;
    this.b;
    this.r;
    this.rArCrD;
  }
}

class SigmaAuxiliaries {
  constructor() {
    this.n;
    this.m;
    this.g;
    this.h;
    this.g_new;
    this.hs;

  }
}

class ProcessRedeemInput {
  constructor() {
    this.cred;
    this.token;
    this.pk;
    this.z1;
    this.z2;
    this.A;
    this.B;
    this.v;
    this.k;
  }
}


class CreateEscorwParams{
  constructor() {
    //k, td, v, randomString
    this.k;
    this.td;
    this.v;
    this.randomString;
  }
}

class CT {
    constructor() {
        this.XX = zero;
        this.YY = zero;
        this.nonce = 0;
    }
}

class G1Point {
    constructor(x, y) {
        this.X = x;
        this.Y = y;
    }
}

module.exports = { 
  R1Proof,
  SigmaProof,
  CT, 
  G1Point, 
  ProofEscrow,
  TwistedElgamalParams,
  EscrowStatement,
  RedeemStatement,
  R1Auxiliaries,
  AuxRedeem1,
  AuxRedeem2,
  RequestRedeemInput,
  AuxprocessRedeem,
  RedeemProofStep2,
  AuxR1ProofPart1Input,
  AuxR1ProofPart2Input,
  SigmaAuxiliaries,
  ProcessRedeemInput,
  CreateEscorwParams
};
