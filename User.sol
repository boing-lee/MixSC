pragma solidity >=0.5.0 <0.6.0;
pragma experimental ABIEncoderV2;

import "./library/BN128.sol";
import "./SDCTSystem.sol";
import "./Primitives.sol";
import "./SDCTSetup.sol";
import "./MixSC.sol";
import "./library/SafeMath.sol";

contract User{
    using BN128 for BN128.G1Point;
    using BN128 for uint256;
    // using SafeMath for uint256;

    SDCTSetup sdctSetup;
    SDCTSystem sdctSystem;
    MixSC mixSC;
    BN128.G1Point public gBase;
    struct CreateEscrowParams {
        uint256 k;//用户设定随机数
        uint256 td;//用户设定随机数
        uint256 v;//明文
        // address addrMixSC,//MixSC合约地址
        string randomString;//随机的字符串用于生成生成元（目前有些问题）
    }

    struct RedeemProofStep2 {
        BN128.G1Point A;
        BN128.G1Point B;
        uint256 z1;
        uint256 z2;
    }

    event CreateEscrowEvent(
        SDCTSystem.CT cesc,
        MixSC.Proof_Escrow proofEscrow
    );
    event VerifyTokenEvent(BN128.G1Point g1, BN128.G1Point g2);

    

    constructor(
        // address sdctSystem_,
        address sdctSetUp_,
        address MixSC_
    ) public {
        // address sdctSetUp_ = address(0x63e655E9C9A8a78d7E60f9D0182EF091d39B7FD8);
        // address MixSC_ = address(0x42Edf5E18C88056E92782FD3D0495ada11FCC4be);
        sdctSetup = SDCTSetup(sdctSetUp_);
        // sdctSystem = SDCTSystem(sdctSystem_);
        mixSC = MixSC(MixSC_);
        gBase.X = 1;
        gBase.Y = 2;
    }


    function CreateEscrow(
        BN128.G1Point memory pke,//托管方公钥
        BN128.G1Point memory pkr,//提币方公钥
        // uint256 k,//用户设定随机数
        // uint256 td,//用户设定随机数
        // uint256 v,//明文
        // // address addrMixSC,//MixSC合约地址
        // string memory randomString//随机的字符串用于生成生成元（目前有些问题）
        CreateEscrowParams memory crEscParams
    ) public returns(SDCTSystem.CT memory, MixSC.Proof_Escrow memory){
        // ) public returns(uint256){
        //BN128.G1Point g = SDCTSetup.generatePointByString(str);
        SDCTSystem.CT memory cesc;
        BN128.G1Point[2] memory base;
        // uint256 k =  uint(keccak256(abi.encodePacked(msg.sender,block.timestamp,block.difficulty))).mod();
        Primitives.TwistedElgammalParams memory twElParams;
        {
            twElParams.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);
            twElParams.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);
            twElParams.k = crEscParams.k;
            twElParams.v = crEscParams.v;
            twElParams.pk = pke;
        
            (cesc.X, cesc.Y) = Primitives.TwistedElgammal(twElParams);
        }
        //确定随机数td,确定一个新的生成元f
        BN128.G1Point memory f = gBase.mul(uint(keccak256(abi.encodePacked(crEscParams.randomString))).mod());
        // BN128.G1Point memory f; //还没有设置值。。。。TODO
        //
        //num[1] r
        //num[2] c
        //num[3] z
        uint256[4] memory num;
        // num[0] = uint(keccak256(abi.encodePacked(block.timestamp,block.difficulty, msg.sender))).mod();
        BN128.G1Point memory token = f.mul(crEscParams.td);
        num[1] = uint(keccak256(abi.encodePacked(block.timestamp,block.difficulty, block.timestamp, msg.sender))).mod();
        BN128.G1Point memory R = f.mul(num[1]);
        num[2] = uint256(keccak256(abi.encodePacked(token.X,token.Y, R.X, R.Y))).mod();
        num[3] = uint(num[1].add( (num[2].mul(crEscParams.td).mod() ) )).mod();
        

        MixSC.Proof_Escrow memory proofEscrow;
        proofEscrow.pk = pke;
        proofEscrow.tokenKind = 0;
        proofEscrow.token = token;
        proofEscrow.mu = generateMu(pke, pkr, crEscParams.k);
        proofEscrow.R = R;
        proofEscrow.GBase = f;
        proofEscrow.z = num[3];
    
        emit CreateEscrowEvent(cesc, proofEscrow);
        // mixSC.processEscrow(cesc, pke, 0, token, pke , R, f, num[3]);
        mixSC.processEscrow(cesc, proofEscrow);
        
    //    return verifyToken(proofEscrow.token, proofEscrow.R, proofEscrow.GBase, proofEscrow.z);

        return (cesc, proofEscrow);
    }

// //验证Token
//     //采用非交互的schnorr协议
//     function verifyToken(
//         BN128.G1Point memory token,//token当成PK公钥来看
//         BN128.G1Point memory R, //r * G
//         BN128.G1Point memory GBase,
//         uint256 z //
//     ) private returns(uint256) {
//         //schnorr proof verifier
//         uint256 c = uint256(keccak256(abi.encodePacked(token.X,token.Y, R.X, R.Y))).mod();
//         BN128.G1Point memory g1 = GBase.mul(z);
//         BN128.G1Point memory g2 = token.mul(c).add(R);
//         emit VerifyTokenEvent(g1,g2);
//         if(g1.eq(g2)) {
//             return 1;
//         } else {
//             return 0;
//         }
//     }






    function generateMu(BN128.G1Point memory pke, BN128.G1Point memory pkr, uint256 k) internal returns(BN128.G1Point memory) {
        return pkr.add(pke.neg()).mul(k);
    }


    struct AuxRedeem1 {
        uint256 r;
        uint256 a;
        uint256 b;
        uint256 l;
        uint256 m;
        uint256 n;
        SDCTSystem.CT tmpCesc;
        SDCTSystem.CT cesc;
        BN128.G1Point mu;
        BN128.G1Point f_base;
        BN128.G1Point token;
        SDCTSystem.CT tmpCred;
    }

    struct AuxRedeem2 {
        uint256 N;
        BN128.G1Point[] clist1;
        BN128.G1Point[] clist2;
        uint256 rB;
        uint256[] rouk;
        BN128.G1Point newG_ck;
        BN128.G1Point[] hs;
        uint256[] delta;
        BN128.G1Point[] Gk1;
        BN128.G1Point[] Gk2;
    }

    struct RequestRedeemInput {
        uint256 k;
        uint256 td;
        uint256 v;
        BN128.G1Point pkr;
        string randomString;
    }

    struct AuxprocessRedeem {
        BN128.G1Point A;
        BN128.G1Point B;
        BN128.G1Point C;
        BN128.G1Point D;
        uint256[] f;
        uint256 zA;
        uint256 zC;
        uint256 z;
        uint256 tmpz;
    }

    event RequestRedeemAuxRedeem1(AuxRedeem1 auxRedeem1);
    event RequestRedeemPrint(string str);
    event RequestRedeemStep1(SDCTSystem.CT cred);
    event RequestRedeemStep2(RedeemProofStep2 rps);
    event RequestRedeemStep3_1(AuxRedeem2 auxRedeem2, AuxprocessRedeem auxProcessRed);
    event RequestRedeemStep3_2(BN128.G1Point[] group_elements, uint256 challenge_x);
    function RequestRedeem(
        // SDCTSystem.CT memory cesc,
        // uint256 k,//escorw中用的随机数
        // uint256 td,//escorw中用的随机数
        // uint256 v,
        // string memory randomString,
        // // BN128.G1Point memory mu,
        // BN128.G1Point memory pkr
        RequestRedeemInput memory redInput
    ) public {
        // uint256 l;//标识是哪个cesc
        // uint256 m;
        // uint256 n = 2;
        AuxRedeem1 memory auxRedeem1;
        AuxRedeem2 memory auxRedeem2;
        AuxprocessRedeem memory auxProcessRed;
        // BN128.G1Point memory mu;
        auxRedeem1.f_base = gBase.mul(uint(keccak256(abi.encodePacked(redInput.randomString))).mod());
        auxRedeem1.token = auxRedeem1.f_base.mul(redInput.td);
        {
            uint256 len = mixSC.getEscPoolLength();
            auxRedeem2.N = len;
            MixSC.EscrowStatement memory statement;
            uint256 i;
            for(i = 0; i < len; i++) {
                statement = mixSC.getEscPoolItemByIndex(i);
                if(!statement.token.eq(auxRedeem1.token)) continue;
                else break;
            }
            require(i < len, "token ERROR!");
            auxRedeem1.cesc = statement.cesc;
            auxRedeem1.mu = statement.mu;
            auxRedeem1.l = i;

             //获取l的二进制长度m
            auxRedeem1.m = Primitives.getMi(len);
            auxRedeem1.n = 2;
        }


        emit RequestRedeemAuxRedeem1(auxRedeem1);
       

        // SDCTSystem.CT memory tmpCesc;
        auxRedeem1.tmpCesc.X = auxRedeem1.cesc.X.add(auxRedeem1.mu);
        auxRedeem1.tmpCesc.Y = auxRedeem1.cesc.Y;
        auxRedeem1.tmpCesc.nonce = auxRedeem1.cesc.nonce;
        SDCTSystem.CT memory cred;
        //cesc生成cred用于后续验证
        Primitives.TwistedElgammalParams memory twElParams;
        twElParams.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);
        twElParams.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);
        twElParams.k = redInput.td;
        twElParams.v = 0;
        twElParams.pk = redInput.pkr;

        emit RequestRedeemPrint("step1 near 252 is OK");

        // SDCTSystem.CT memory tmpCred;
        (auxRedeem1.tmpCred.X, auxRedeem1.tmpCred.Y) = Primitives.TwistedElgammal(twElParams);
        cred.X = auxRedeem1.tmpCesc.X.add(auxRedeem1.tmpCred.X);
        cred.Y = auxRedeem1.tmpCesc.Y.add(auxRedeem1.tmpCred.Y);

        emit RequestRedeemStep1(cred);
        emit RequestRedeemPrint("step1 near 257 is OK");


        //第二步，对密文格式进行验证，生成pf_enc（即rps）
        RedeemProofStep2 memory rps;
        {
            auxRedeem1.r = redInput.k.add(redInput.td);
            auxRedeem1.a = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp, msg.sender))).mod();
            auxRedeem1.b = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender, block.difficulty, block.timestamp))).mod();
            rps.A = redInput.pkr.mul(auxRedeem1.a);
            rps.B = twElParams.g.mul(auxRedeem1.a).add(twElParams.h.mul(auxRedeem1.b));
            uint256 e = uint(keccak256(abi.encodePacked(rps.A.X, rps.A.Y, rps.B.X, rps.B.Y))).mod();
            rps.z1 = auxRedeem1.a.add(e.mul(auxRedeem1.r)).mod();
            rps.z2 = auxRedeem1.b.add(e.mul(redInput.v)).mod();
        }
        emit RequestRedeemStep2(rps);
        emit RequestRedeemPrint("step2 near 277 is OK");


        // //第三步，生成提币合法性证明pf_legal
       
        auxRedeem2.clist1 = new BN128.G1Point[](auxRedeem2.N);
        auxRedeem2.clist2 = new BN128.G1Point[](auxRedeem2.N);
        for (uint256 i = 0; i < auxRedeem2.N; i++) {
            auxRedeem2.clist1[i] = cred.X.add(mixSC.getEscPool()[i].cesc.X.add(mixSC.getEscPool()[i].mu).neg());
            auxRedeem2.clist2[i] = cred.Y.add(mixSC.getEscPool()[i].cesc.Y.neg());
        }


        auxRedeem2.rB = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp, msg.sender))).mod();
        auxRedeem2.rouk = new uint256[](auxRedeem1.m);
        for(uint i = 0; i < auxRedeem1.m; i++) {
            auxRedeem2.rouk[i] = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp, i))).mod();
        }
        auxRedeem2.newG_ck = gBase.mul(uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp))).mod());
        
        //生成hs
        auxRedeem2.hs = Primitives.geths(auxRedeem1.m,auxRedeem1.n,gBase);

        // //生成delta
        auxRedeem2.delta = Primitives.getDelta(Primitives.convertToNal(auxRedeem1.l,auxRedeem1.n,auxRedeem1.m), auxRedeem1.m);
        
        auxProcessRed.B = Primitives.commitBits(
            auxRedeem2.newG_ck,
            auxRedeem2.hs,
            auxRedeem2.delta, 
            auxRedeem2.rB
        );

        emit RequestRedeemPrint("step2 near 314 is OK");
       
        // BN128.G1Point[] memory Gk1 = new BN128.G1Point[](m);
        // BN128.G1Point[] memory Gk2 = new BN128.G1Point[](m);
        auxRedeem2.Gk1 = new BN128.G1Point[](auxRedeem1.m);
        auxRedeem2.Gk2 = new BN128.G1Point[](auxRedeem1.m);
        {
            //生成p_i_k(很复杂)
            uint256[] memory p_i_k = new uint256[](auxRedeem2.N*auxRedeem1.m); //N行m列
            for(uint256 i = 0; i < auxRedeem2.N; i++) {
                uint256[] memory tmp_p_i = Primitives.GetP(auxRedeem1.l, i, auxRedeem1.m);
                for(uint256 j = 0; j < auxRedeem1.m; j++) {
                    p_i_k[i*auxRedeem1.m+j] = tmp_p_i[j];
                }
            }

            //生成GK1,GK2
            twElParams.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);
            twElParams.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);
            twElParams.v = 0;
            for(uint256 idx_k = 0; idx_k < auxRedeem1.m; idx_k++) {
                BN128.G1Point memory t1 = BN128.zero();
                BN128.G1Point memory t2 = BN128.zero();
                for(uint256 i = 0; i < auxRedeem2.N; i++) {
                    t1 = t1.add(auxRedeem2.clist1[i].mul(p_i_k[i*auxRedeem1.m+idx_k]));
                    t2 = t2.add(auxRedeem2.clist2[i].mul(p_i_k[i*auxRedeem1.m+idx_k]));
                }
                twElParams.k = auxRedeem2.rouk[idx_k];
                BN128.G1Point[2] memory tmpRight;
                (tmpRight[0], tmpRight[1]) = Primitives.TwistedElgammal(
                    // aux.g,
                    // aux.h[0],
                    // 0,
                    // proof.z,
                    // pk
                    twElParams
                );
                auxRedeem2.Gk1[idx_k] = t1.add(tmpRight[0]);
                auxRedeem2.Gk2[idx_k] = t2.add(tmpRight[1]);
            }
        }
    
    // emit RequestRedeemStep3_1(auxRedeem2, auxProcessRed);
    emit RequestRedeemPrint("step2 near 356 is OK");
        // //生成A,C,D
        // {
            uint256[] memory a_R1ProofPart1;
            uint256[3] memory rArCrD;
            AuxR1ProofPart1Input memory auxR1Part1;
            auxR1Part1.g = auxRedeem2.newG_ck;
            auxR1Part1.hs = auxRedeem2.hs;
            auxR1Part1.B = auxProcessRed.B;
            auxR1Part1.b = auxRedeem2.delta;
            auxR1Part1.r = auxRedeem2.rB;
            auxR1Part1.m = auxRedeem1.m;
            auxR1Part1.n = auxRedeem1.n;
            (auxProcessRed.A,auxProcessRed.C,auxProcessRed.D,rArCrD, a_R1ProofPart1) = generateR1ProofPart1(
                // auxRedeem2.newG_ck, auxRedeem2.hs, auxProcessRed.B, auxRedeem2.delta, auxRedeem2.rB,auxRedeem1.m,auxRedeem1.n
                auxR1Part1
                );
            // emit RequestRedeemStep3_1(auxRedeem2, auxProcessRed);
            //生成对应的challenge_X
            uint256 challenge_x;
            BN128.G1Point[] memory group_elements = new BN128.G1Point[](
                auxRedeem2.Gk1.length + auxRedeem2.Gk2.length + 4
            );
            group_elements[0] = auxProcessRed.A;
            group_elements[1] = auxProcessRed.B;
            group_elements[2] = auxProcessRed.C;
            group_elements[3] = auxProcessRed.D;
            for (uint256 i = 0; i < auxRedeem2.Gk1.length; i++) {
                group_elements[i + 4] = auxRedeem2.Gk1[i];
            }
            for (uint256 i = 0; i < auxRedeem2.Gk2.length; i++) {
                group_elements[auxRedeem2.Gk1.length + i + 4] = auxRedeem2.Gk2[i];
            }
            challenge_x = Primitives.generateChallenge(group_elements);
        
            // uint256[] memory f;
            // uint256 zA;
            // uint256 zC;
            //生成f,zA,zC
            {
                AuxR1ProofPart2Input memory auxPart2Input;
                auxPart2Input.m = auxRedeem1.m;
                auxPart2Input.n = auxRedeem1.n;
                auxPart2Input.challenge_x = challenge_x;
                auxPart2Input.a = a_R1ProofPart1;
                auxPart2Input.b = auxRedeem2.delta;
                auxPart2Input.r = auxRedeem2.rB;
                auxPart2Input.rArCrD = rArCrD;
                (auxProcessRed.f, auxProcessRed.zA, auxProcessRed.zC) = generateR1ProofPart2(
                    // auxRedeem1.m,auxRedeem1.n,challenge_x,a_R1ProofPart1,auxRedeem2.delta,auxRedeem2.rB, rArCrD
                    auxPart2Input
                    );
            }
            // emit RequestRedeemStep3_2(group_elements, challenge_x);
            
            // uint256 z;
            // uint256 tmpz;
            auxProcessRed.tmpz = 0;
            for(uint256 i = 0; i < auxRedeem1.m; i++) {
                auxProcessRed.tmpz = auxProcessRed.tmpz.add( auxRedeem2.rouk[i].mul(challenge_x.modExp(i)).mod() );
            }
            auxProcessRed.z = auxRedeem1.r.mul(challenge_x.modExp(auxRedeem1.m)).mod();
            auxProcessRed.z = auxProcessRed.z.sub(auxProcessRed.tmpz).mod();
            emit RequestRedeemStep3_1(auxRedeem2, auxProcessRed);
            emit RequestRedeemPrint("step2 near 419 is OK");
            
            Verifier.SigmaProof memory proof_format;

            Verifier.R1Proof memory r1Proof;
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

            Verifier.SigmaAuxiliaries memory aux_format;
            //填充参数
            aux_format.n = auxRedeem1.n;
            aux_format.m = auxRedeem1.m;
            aux_format.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);  //setup中， 用于Tw加密  ek
            aux_format.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);  //用于Tw加密
            aux_format.g_new = auxRedeem2.newG_ck;  //新生成的，用于CommitBits  ck
            aux_format.hs = auxRedeem2.hs;  //是生成的hs用于CommitBits


            MixSC.ProcessRedeemInput memory input;
            input.cred = cred;
            input.token = 0;
            input.pk = redInput.pkr;
            input.A = rps.A;
            input.B = rps.B;
            input.z1 = rps.z1;
            input.z2 = rps.z2;
            input.v = redInput.v;
            input.k = redInput.k;

            mixSC.processRedeem(proof_format, aux_format, input);
            

        // }


    }

struct AuxR1ProofPart1Input {
    BN128.G1Point g;
    BN128.G1Point[] hs;
    BN128.G1Point B;
    uint256[] b;
    uint256 r;
    uint256 m;
    uint256 n;
}



struct AuxR1ProofPart1Tmp {
    uint256 rA;
    uint256 rC;
    uint256 rD;
    BN128.G1Point A;
    BN128.G1Point C;
    BN128.G1Point D;
    uint256[] tmpC;
    uint256[] tmpD;
}

    function generateR1ProofPart1(
        // BN128.G1Point memory g,
        // BN128.G1Point[] memory hs,
        // BN128.G1Point memory B,
        // uint256[] memory b,
        // uint256 r,
        // uint256 m,
        // uint256 n
        AuxR1ProofPart1Input memory auxInput
    ) internal returns(
        BN128.G1Point memory,
        BN128.G1Point memory, 
        BN128.G1Point memory,
        uint256[3] memory,
        uint256[] memory
        ) {
        AuxR1ProofPart1Tmp memory auxTmp;
        auxTmp.rA = uint(keccak256(abi.encodePacked(block.difficulty, msg.sender, block.timestamp))).mod();
        auxTmp.rC = uint(keccak256(abi.encodePacked(msg.sender, block.timestamp))).mod();
        auxTmp.rD = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp))).mod();
        uint256[] memory a = new uint256[](auxInput.m.mul(auxInput.n));
        for(uint256 j = 0; j < auxInput.m; j++) {
            uint256 tmpSum = 0;
            for(uint256 i = 1; i < auxInput.n; i++) {
                a[j*auxInput.n+i] =  uint(keccak256(abi.encodePacked(j, i, msg.sender, block.timestamp))).mod();
                tmpSum = tmpSum.add(a[j*auxInput.n+i]);
            }
            a[j*auxInput.n + 0] = tmpSum.neg();
        }
        

        auxTmp.A = Primitives.commitBits(auxInput.g,auxInput.hs,a,auxTmp.rA);
        auxTmp.tmpC = new uint256[](auxInput.m.mul(auxInput.n));
        {
           uint256[3] memory base;
           base[0] = 1;
           base[1] = 2;
            for(uint256 j = 0; j < auxInput.m; j++) {
                for(uint256 i = 0; i < auxInput.n; i++) {
                    base[2] = base[0].sub(base[1].mul(auxInput.b[j*auxInput.n+i]));
                    auxTmp.tmpC[j*auxInput.n+i] =  a[j*auxInput.n+i].mul(base[2]).mod();
                }
            }
        }
        auxTmp.C = Primitives.commitBits(auxInput.g,auxInput.hs,auxTmp.tmpC, auxTmp.rC);
        auxTmp.tmpD = new uint256[](auxInput.m.mul(auxInput.n));
        for(uint256 j = 0; j < auxInput.m; j++) {
            for(uint256 i = 0; i < auxInput.n; i++) {
                auxTmp.tmpD[j*auxInput.n+i] =  a[j*auxInput.n+i].mul(a[j*auxInput.n+i]).mod().neg();
            }
        }
        auxTmp.D = Primitives.commitBits(auxInput.g, auxInput.hs, auxTmp.tmpD, auxTmp.rD);
        uint256[3] memory rArCrD = [auxTmp.rA, auxTmp.rC, auxTmp.rD];  
        
        return (auxTmp.A, auxTmp.C, auxTmp.D, rArCrD, a);
    }


struct AuxR1ProofPart2Input {
    uint256 m;
    uint256 n;
    uint256 challenge_x;
    uint256[] a;
    uint256[] b;
    uint256 r;
    uint256[3] rArCrD;
}


    function generateR1ProofPart2(
        // uint256 m,
        // uint256 n,
        // uint256 challenge_x,
        // uint256[] memory a,
        // uint256[] memory b,
        // uint256 r,
        // uint256[3] memory rArCrD
        AuxR1ProofPart2Input memory auxInput
    ) internal returns(
        uint256[] memory,
        uint256,
        uint256
    ) {
        uint[] memory f = new uint256[](auxInput.m.mul(auxInput.n));
        for(uint256 j = 0; j < auxInput.m; j++) {
            for(uint256 i = 0; i < auxInput.n; i++) {
                f[j*auxInput.n + i] = auxInput.b[j*auxInput.n+i].mul(auxInput.challenge_x).mod().add(auxInput.a[j*auxInput.n+i]);
            }
        }
        uint256 zA = auxInput.r.mul(auxInput.challenge_x).add(auxInput.rArCrD[0]).mod();
        uint256 zC = auxInput.rArCrD[1].mul(auxInput.challenge_x).add(auxInput.rArCrD[2]);
        return (f, zA, zC);
    }

}
