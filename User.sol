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
    using SafeMath for uint256;

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
        //num[0] td
        //num[1] r
        //num[2] c
        //num[3] z
        uint256[4] memory num;
        // num[0] = uint(keccak256(abi.encodePacked(block.timestamp,block.difficulty, msg.sender))).mod();
        BN128.G1Point memory token = f.mul(crEscParams.td);
        num[1] = uint(keccak256(abi.encodePacked(block.timestamp,block.difficulty, block.timestamp, msg.sender))).mod();
        BN128.G1Point memory R = f.mul(num[1]);
        num[2] = uint256(keccak256(abi.encodePacked(token.X,token.Y, R.X, R.Y))).mod();
        num[3] = uint(num[1] + (num[2] * crEscParams.td).mod()).mod();
        

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


    function RequestRedeem(
        SDCTSystem.CT memory cesc,
        uint256 td,
        BN128.G1Point memory mu,
        BN128.G1Point memory pkr
    ) public {
        SDCTSystem.CT memory tmpCesc;
        tmpCesc.X = cesc.X.add(mu);
        tmpCesc.Y = cesc.Y;
        tmpCesc.nonce = cesc.nonce;
        SDCTSystem.CT memory cred;

        
        Primitives.TwistedElgammalParams memory twElParams;
        twElParams.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);
        twElParams.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);
        twElParams.k = td;
        twElParams.v = 0;
        twElParams.pk = pkr;

        SDCTSystem.CT memory tmpCred;
        (tmpCred.X, tmpCred.Y) = Primitives.TwistedElgammal(twElParams);
        cred.X = tmpCesc.X.add(tmpCred.X);
        cred.Y = tmpCesc.Y.add(tmpCred.Y);


    }








}








