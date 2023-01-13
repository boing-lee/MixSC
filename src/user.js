const BN = require("bn.js");
const { R1Proof, SigmaProof, CT, G1Point, TwistedElgamalParams, ProofEscrow, EscrowStatement,
    AuxRedeem1,
    AuxRedeem2,
    RequestRedeemInput,
    AuxprocessRedeem,
    RedeemProofStep2,
    AuxR1ProofPart1Input, AuxR1ProofPart2Input, SigmaAuxiliaries, ProcessRedeemInput } = require("./types");
const { curve, g, h, zero } = require("./params");
const { TwistedElgamal, randomExponent, hashString2Int, geths, getDelta, convertToNal, commitBits, GetP, getMi, generateChallenge } = require("./primitives");
const { verifyProofEscrow, verifyRedeemProofFormat } = require("./verifier");
const { serialize, serializeCT, serializeProofEscrow, toBytes,serializeCreateEscorwParams,
    serializeRequestRedeemInput } = require("./serialize");
const { red } = require("bn.js");

//user端只负责生成proof
//verifier负责验证生成的proof
class User {
    constructor(web3, mixSCContract, sdctSystem,userContract, account) {
        this.web3 = web3;
        this.sdctSystem = sdctSystem;
        this.mixSCContract = mixSCContract;
        this.userContract = userContract;
        this.account = account;
        this.value = new BN(0);

        this.cs = [];
        this.rs = [];
        this.esc_token_pool = {};
        this.esc_mu_pool = {};
        this.esc_pool = [];
    }


    //包含内容
    //1、测试时间：本地js测试CreateEscorw，verifyProofEscrow
    //2、测试gas和bytes：调用合约方法
    async Escrow(pke, pkr, crEscParams) {
        let startTime = Date.now();

        let [cesc, proofEscrow] = CreateEscorw(pke, pkr, crEscParams);

        let endTime = Date.now();
        console.log("The time of CreateEscorw:", endTime - startTime, "ms   ");

        startTime = Date.now();
        if (this.esc_token_pool[hashString2Int(JSON.stringify(proofEscrow.token))]  == true
            || this.esc_mu_pool[hashString2Int(JSON.stringify(proofEscrow.mu))] == true) {
            console.log("line 51 is false!!");
            return false;
        }
        if (!verifyProofEscrow(proofEscrow)) {
            console.log("userjs line 55 verifyProofEscrow is false!!!");
            return false;
        }
        endTime = Date.now();
        console.log("The time of verifyProofEscrow:", endTime - startTime, "ms    ");

        let statement = new EscrowStatement();
        statement.cesc = cesc;
        statement.token = proofEscrow.token;
        statement.mu = proofEscrow.mu;
        this.esc_pool.push(statement);
        this.esc_token_pool[hashString2Int(JSON.stringify(proofEscrow.token))] = true;
        this.esc_mu_pool[hashString2Int(JSON.stringify(proofEscrow.mu))] = true;

        //暂时放在这里
        startTime = Date.now();
        const result1 = await this.sdctSystem.depositAccountETH(
            serialize(pke),
            { from: this.account, value: 1e18 }
        );
        endTime = Date.now();
        console.log("The time of depositAccountETH:", endTime - startTime, "ms    ");

        //call调用返回return值，但是不能返回tx的一些状态，如汽油,hashcode,等等（不能重复调用，会导致重复生成）
        const result2 = await this.userContract.CreateEscrow.call(serialize(pke), serialize(pkr), serializeCreateEscorwParams(crEscParams) );
        
        // const result = await this.contract.processEscrow(serializeCT(cesc), serializeProofEscrow(proofEscrow),
            // { from: this.account, });
        const result = await this.mixSCContract.processEscrow(result2[0], result2[1], {from: this.account,});

        //console.log("processEscrow的整个结果：",result);
        const tx = await this.web3.eth.getTransaction(result.tx);
        //console.log("tx的详细信息：",tx);
        console.log("processEscrow的Gas为：",tx.gas);
        console.log("Escrow tx input size:", (tx.input.length - 2) / 2, "Bytes"); // 2 hex char = 1 byte

        return true;

    }


    //包含内容
    //1、测试时间：本地js测试CreateRedeem，VerifyRedeem
    //2、测试gas和bytes：调用合约方法
    async Redeem(redInput, bobAccount) {

        let startTime, endTime;
        startTime = Date.now();
        let [proof_format, aux_format, input] = this.CreateRedeem(redInput);

        endTime = Date.now();
        console.log("The time of CreateRedeem:", endTime - startTime, "ms      ");

        startTime = Date.now();
        let res = this.VerifyRedeem(proof_format, aux_format, input);
        endTime = Date.now();
        console.log("The time of VerifyRedeem:", endTime - startTime, "ms      ");
        console.log("The result of VerifyRedeem is :", res, "         ");

        const result = await this.userContract.CreateRedeem.call(serializeRequestRedeemInput(redInput));
        //console.log("resultRedeem:",result);

        const result2 = await this.mixSCContract.processRedeem(result[0], result[1], result[2]);
        const tx = await this.web3.eth.getTransaction(result2.tx);
        //console.log("tx的详细信息：",tx);
        console.log("processRedeem的Gas为：",tx.gas);
        console.log("Redeem tx input size:", (tx.input.length - 2) / 2, "Bytes"); // 2 hex char = 1 byte

        const burnResult = await this.mixSCContract.burnEth(bobAccount, 1, serialize(redInput.pkr));
        //console.log("burnResult:",burnResult);

        //仅js的结果
        return res;

    }


    VerifyRedeem(proof_format, aux_format, input) {
        
        //startTime = Date.now();
        let res = verifyRedeemProofFormat(proof_format, aux_format, input, this.esc_pool);
        //endTime = Date.now();
        //console.log("The time of depositAccountETH:", endTime - startTime, "ms      ");
        return res;
    }

    CreateRedeem(redInput) {
        let auxRedeem1 = new AuxRedeem1();
        let auxRedeem2 = new AuxRedeem2();
        let auxProcessRed = new AuxprocessRedeem();
        auxRedeem1.f_base = g.mul(hashString2Int(redInput.randomString));
        auxRedeem1.token = auxRedeem1.f_base.mul(redInput.td);
        let len = this.esc_pool.length;

        console.log("cesc pool的长度为：++++++++++++++++++++++:", len);

        auxRedeem2.N = len;
        let i;
        let flag = false;
        let statement;
        for (i = 0; i < len; i++) {
            statement = this.esc_pool[i];
            if (!statement.token.eq(auxRedeem1.token)) continue;
            else {
                flag = true;
                break;
            };
        }

        if (!flag) {
            console.log("user.js,near line 102 token is failed");
            return false
        };
        auxRedeem1.cesc = statement.cesc;
        auxRedeem1.mu = statement.mu;
        auxRedeem1.l = i;
        auxRedeem1.m = getMi(len);//len为number
        auxRedeem1.n = 2;
        auxRedeem1.tmpCesc.XX = auxRedeem1.cesc.XX.add(auxRedeem1.mu);
        auxRedeem1.tmpCesc.YY = auxRedeem1.cesc.YY;
        auxRedeem1.tmpCesc.nonce = auxRedeem1.cesc.nonce;

        let cred = new CT();
        let twElParams = new TwistedElgamalParams();
        twElParams.g = g;
        twElParams.h = h;
        twElParams.k = redInput.td;
        twElParams.v = new BN(0);
        twElParams.pk = redInput.pkr;
        let tmpCred = TwistedElgamal(twElParams);
        cred.XX = auxRedeem1.tmpCesc.XX.add(tmpCred.XX);
        cred.YY = auxRedeem1.tmpCesc.YY.add(tmpCred.YY);

        //step2
        let rps = new RedeemProofStep2();
        auxRedeem1.r = redInput.k.add(redInput.td);
        auxRedeem1.a = randomExponent();
        auxRedeem1.b = randomExponent();
        rps.A = redInput.pkr.mul(auxRedeem1.a);
        rps.B = twElParams.g.mul(auxRedeem1.a).add(twElParams.h.mul(auxRedeem1.b));
        let e = hashString2Int(JSON.stringify(rps.A) + JSON.stringify(rps.B));
        rps.z1 = auxRedeem1.a.add(e.mul(auxRedeem1.r));
        rps.z2 = auxRedeem1.b.add(e.mul(redInput.v));


        // let tmp = redInput.pkr.mul(rps.z1);
        // let actual = cred.XX.mul(e).add(rps.A);
        // console.log("tmp和actual比较的结果：",  tmp.eq(actual));

        //step3 生成提币合法性证明pf_legal
        auxRedeem1.r = redInput.td;
        auxRedeem2.clist1 = new Array(auxRedeem2.N);
        auxRedeem2.clist2 = new Array(auxRedeem2.N);
        for (i = 0; i < auxRedeem2.N; i++) {
            auxRedeem2.clist1[i] = cred.XX.add(this.esc_pool[i].cesc.XX.add(this.esc_pool[i].mu).neg());
            auxRedeem2.clist2[i] = cred.YY.add(this.esc_pool[i].cesc.YY.neg());
        }

        auxRedeem2.rB = randomExponent();
        auxRedeem2.rouk = new Array(auxRedeem1.m);
        for (i = 0; i < auxRedeem1.m; i++) {
            auxRedeem2.rouk[i] = randomExponent();
        }
        auxRedeem2.newG_ck = g.mul(randomExponent());

        //生成hs
        auxRedeem2.hs = geths(auxRedeem1.m, auxRedeem1.n, g);

        //生成delta number
        //感觉l,n,m都是数字类型。。。。。
        auxRedeem2.delta = getDelta(convertToNal(auxRedeem1.l, auxRedeem1.n, auxRedeem1.m), auxRedeem1.m);
        let BnDelta = new Array();
        for (let j = 0; j < auxRedeem2.delta.length; j++) {
            BnDelta.push(new BN(auxRedeem2.delta[j]));
        }

        auxProcessRed.B = commitBits(
            auxRedeem2.newG_ck,
            auxRedeem2.hs,
            BnDelta,
            auxRedeem2.rB
        );
        // auxRedeem2.GK1 = new Array(auxRedeem1.m);
        // auxRedeem2.GK2 = new Array(auxRedeem1.m);
        auxRedeem2.a = new Array(auxRedeem1.m * auxRedeem1.n);
        for (let j = 0; j < auxRedeem1.m; j++) {
            let tmpSum = new BN(0);
            for (i = 1; i < auxRedeem1.n; i++) {
                auxRedeem2.a[j * auxRedeem1.n + i] = hashString2Int(String(j) + String(i));
                tmpSum = tmpSum.add(auxRedeem2.a[j * auxRedeem1.n + i]);
            }
            auxRedeem2.a[j * auxRedeem1.n + 0] = tmpSum.neg();
        }
        //生成p_i_k(很复杂)
        let p_i_k = new Array(auxRedeem2.N * auxRedeem1.m);//为BN类型
        for (i = 0; i < auxRedeem2.N; i++) {
            let tmp_p_i = GetP(auxRedeem1.l, i, auxRedeem1.m, auxRedeem2.a);//TODO
            for (let j = 0; j < auxRedeem1.m; j++) {
                p_i_k[i * auxRedeem1.m + j] = tmp_p_i[j];//BN
            }
        }
        //生成GK1,GK2
        twElParams.g = g;
        twElParams.h = h;
        twElParams.v = new BN(0);
        for (let idx_k = 0; idx_k < auxRedeem1.m; idx_k++) {
            let t1 = zero;
            let t2 = zero;
            for (i = 0; i < auxRedeem2.N; i++) {
                t1 = t1.add(auxRedeem2.clist1[i].mul(p_i_k[i * auxRedeem1.m + idx_k]));
                t2 = t2.add(auxRedeem2.clist2[i].mul(p_i_k[i * auxRedeem1.m + idx_k]));
            }
            twElParams.k = auxRedeem2.rouk[idx_k];
            let tmpRight = TwistedElgamal(twElParams);
            auxRedeem2.Gk1[idx_k] = t1.add(tmpRight.XX);
            auxRedeem2.Gk2[idx_k] = t2.add(tmpRight.YY);
        }

        let rArCrD = new Array(3);
        let auxR1Part1 = new AuxR1ProofPart1Input();
        auxR1Part1.g = auxRedeem2.newG_ck;
        auxR1Part1.hs = auxRedeem2.hs;
        auxR1Part1.B = auxProcessRed.B;
        //auxR1Part1.b = auxRedeem2.delta;
        auxR1Part1.b = BnDelta;
        auxR1Part1.r = auxRedeem2.rB;
        auxR1Part1.m = auxRedeem1.m;
        auxR1Part1.n = auxRedeem1.n;
        auxR1Part1.a = auxRedeem2.a;
        [auxProcessRed.A, auxProcessRed.C, auxProcessRed.D, rArCrD] = genagenerateR1ProofPart1(auxR1Part1);

        let challenge_x;
        let group_elements = new Array(auxRedeem2.Gk1.length + auxRedeem2.Gk2.length + 4);
        group_elements[0] = auxProcessRed.A;
        group_elements[1] = auxProcessRed.B;
        group_elements[2] = auxProcessRed.C;
        group_elements[3] = auxProcessRed.D;

        for (i = 0; i < auxRedeem2.Gk1.length; i++) {
            group_elements[i + 4] = auxRedeem2.Gk1[i];
        }
        for (i = 0; i < auxRedeem2.Gk2.length; i++) {
            group_elements[auxRedeem2.Gk1.length + i + 4] = auxRedeem2.Gk2[i];
        }
        challenge_x = generateChallenge(group_elements);

        let auxPart2Input = new AuxR1ProofPart2Input();
        auxPart2Input.m = auxRedeem1.m;
        auxPart2Input.n = auxRedeem1.n;
        auxPart2Input.challenge_x = challenge_x;
        auxPart2Input.a = auxRedeem2.a;
        //auxPart2Input.b = auxRedeem2.delta;
        auxPart2Input.b = BnDelta;
        auxPart2Input.r = auxRedeem2.rB;
        auxPart2Input.rArCrD = rArCrD;

        [auxProcessRed.f, auxProcessRed.zA, auxProcessRed.zC] = generateR1ProofPart2(auxPart2Input);//TODO
        auxProcessRed.tmpz = new BN(0);
        for (i = 0; i < auxRedeem1.m; i++) {
            auxProcessRed.tmpz = auxProcessRed.tmpz.add(auxRedeem2.rouk[i].mul(challenge_x.pow(new BN(i))));
        }
        auxProcessRed.z = auxRedeem1.r.mul(challenge_x.pow(new BN(auxRedeem1.m))).sub(auxProcessRed.tmpz);

        let proof_format = new SigmaProof();
        let r1Proof = new R1Proof();
        r1Proof.A = auxProcessRed.A;
        r1Proof.C = auxProcessRed.C;
        r1Proof.D = auxProcessRed.D;
        r1Proof.f = auxProcessRed.f;
        r1Proof.zA = auxProcessRed.zA;
        r1Proof.zC = auxProcessRed.zC;
        //填充参数
        proof_format.B = auxProcessRed.B;
        proof_format.r1Proof = r1Proof;
        proof_format.Gk1 = auxRedeem2.Gk1;
        proof_format.Gk2 = auxRedeem2.Gk2;
        proof_format.z = auxProcessRed.z;

        let aux_format = new SigmaAuxiliaries();
        aux_format.n = auxRedeem1.n;
        aux_format.m = auxRedeem1.m;
        aux_format.g = g  //setup中， 用于Tw加密  ek
        aux_format.h = h;  //用于Tw加密
        aux_format.g_new = auxRedeem2.newG_ck;  //新生成的，用于CommitBits  ck
        aux_format.hs = auxRedeem2.hs;  //是生成的hs用于CommitBits

        let input = new ProcessRedeemInput();
        input.cred = cred;
        input.token = new BN(0);
        input.pk = redInput.pkr;
        input.A = rps.A;
        input.B = rps.B;
        input.z1 = rps.z1;
        input.z2 = rps.z2;
        input.v = redInput.v;
        input.k = redInput.k;

        
        return [proof_format, aux_format, input];
    }

};

function CreateEscorw(pke, pkr, crEscParams) {

    let twElParams = new TwistedElgamalParams();
    twElParams.g = g;
    twElParams.h = h;
    twElParams.k = crEscParams.k;
    twElParams.v = crEscParams.v;
    twElParams.pk = pke;
    let cesc = TwistedElgamal(twElParams);
    //console.log("create cesc :",cesc.XX, "=================",cesc.YY);
    
    let f = g.mul(new BN(hashString2Int(crEscParams.randomString)));
    let token = f.mul(crEscParams.td);
    let numr = randomExponent();
    let R = f.mul(numr);
    let numc = hashString2Int(JSON.stringify(token) + JSON.stringify(R)); //hash将多个变量变成整数
    let numz = numr.add(numc.mul(crEscParams.td));

    let proofEscrow;
    proofEscrow = new ProofEscrow();
    proofEscrow.pk = pke;
    proofEscrow.tokenKind = 0;
    proofEscrow.token = token;
    proofEscrow.mu = (pkr.add(pke.neg())).mul(crEscParams.k);
    proofEscrow.R = R;
    proofEscrow.GBase = f;
    proofEscrow.z = numz;
    proofEscrow.c = numc;
    return [cesc, proofEscrow];
}



function genagenerateR1ProofPart1(auxInput) {
    let rA, rC, rD, A, tmpC;
    rA = randomExponent();
    rC = randomExponent();
    rD = randomExponent();
    A = commitBits(auxInput.g, auxInput.hs, auxInput.a, rA);
    tmpC = new Array(auxInput.m * auxInput.n);

    let base0 = new BN(1);
    let base1 = new BN(2);
    let base2;
    for (let j = 0; j < auxInput.m; j++) {
        for (let i = 0; i < auxInput.n; i++) {
            base2 = base0.sub(base1.mul(auxInput.b[j * auxInput.n + i]));
            tmpC[j * auxInput.n + i] = auxInput.a[j * auxInput.n + i].mul(base2);
        }
    }
    let C = commitBits(auxInput.g, auxInput.hs, tmpC, rC);
    let tmpD = new Array(auxInput.m * auxInput.n);
    for (let j = 0; j < auxInput.m; j++) {
        for (let i = 0; i < auxInput.n; i++) {
            tmpD[j * auxInput.n + i] = auxInput.a[j * auxInput.n + i].mul(auxInput.a[j * auxInput.n + i]).neg();
        }
    }
    let D = commitBits(auxInput.g, auxInput.hs, tmpD, rD);
    let rArCrD = [rA, rC, rD];
    return [A, C, D, rArCrD];
}

function generateR1ProofPart2(auxInput) {
    let f = new Array(auxInput.m * auxInput.n);
    for (let j = 0; j < auxInput.m; j++) {
        for (let i = 1; i < auxInput.n; i++) {
            f[j * auxInput.n + i] = (auxInput.b[j * auxInput.n + i].mul(auxInput.challenge_x)).add(auxInput.a[j * auxInput.n + i]); //都没有取余操作 TODO...后续考虑
        }
    }
    let zA = auxInput.r.mul(auxInput.challenge_x).add(auxInput.rArCrD[0]);
    let zC = auxInput.rArCrD[1].mul(auxInput.challenge_x).add(auxInput.rArCrD[2]);
    return [f, zA, zC];
}


module.exports = { CreateEscorw, User };


