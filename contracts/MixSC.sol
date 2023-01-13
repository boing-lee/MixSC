pragma solidity >=0.5.0 <0.6.0;
pragma experimental ABIEncoderV2;

import "./library/BN128.sol";
import "./SDCTSystem.sol";
import "./Verifier.sol";
import "./library/SafeMath.sol";
contract MixSC{
    using BN128 for BN128.G1Point;
    using BN128 for uint256;
    //using SafeMath for uint256;
    event VerifyTokenEvent(BN128.G1Point g1, BN128.G1Point g2);

    //定义数据结构部分
    address owner;
    mapping(address=>BN128.G1Point) private bind;
    //mapping(uint256=>SDCTSystem.CT) private acc;
    SDCTSystem sdctSystem;
    SDCTSetup sdctSetup;
    struct EscrowStatement {
        SDCTSystem.CT cesc;
        BN128.G1Point token;
        BN128.G1Point mu;
    }

    struct RedeemStatement {
        SDCTSystem.CT cred;
        //BN128.G1Point token;
        //uint256 mu;
    }

    struct Proof_Escrow {
        BN128.G1Point pk;
        uint256 tokenKind;
        BN128.G1Point token;
        BN128.G1Point mu;
        BN128.G1Point R;
        BN128.G1Point GBase;
        uint256 z;
        uint256 c;
    }


    //结构体无法当成key，尝试用结构体的hash值当成key
    mapping(bytes32=>bool) esc_token_pool;
    mapping(bytes32=>bool) esc_mu_pool;
    EscrowStatement[] esc_pool;
    RedeemStatement[] red_pool;

function getEscPool() public view returns(EscrowStatement[] memory) {
    return esc_pool;
}

function getEscPoolLength() public view returns(uint256) {
    return esc_pool.length;
}

function getEscPoolItemByIndex(
    uint256 index
) public view returns(EscrowStatement memory) {
    require(index>=0 && index < esc_pool.length, "Invalid index value!!!");
    return esc_pool[index];
}

    //定义仅管理员操作修饰器
    modifier onlyOwner() {
        require(owner == msg.sender, "only owner!");
        _;
    }

    //定义收取手续费修饰器
    modifier charge() {
        require(msg.value >= 5000);
        _;
    }

    constructor(
        address sdctSystem_,
        address sdctSetUp_
    ) public {
        owner = msg.sender;
        sdctSetup = SDCTSetup(sdctSetUp_);
        sdctSystem = SDCTSystem(sdctSystem_);
        // sdctSetup = SDCTSetup(0xb155F29687E28a4992E30D5D7dC870d821bEea99);
        // sdctSystem = SDCTSystem(0xeD19F971D5fBBe06566DF0a9816F110717775fCA);
    }

    //1、绑定eth地址与PGC地址
    function bindACC(BN128.G1Point memory pk_e) public {
        //bind[msg.sender] = pgc地址
        bind[msg.sender] = pk_e;
        // acc[keccak256(abi.encodePacked(pk_e))] = currentBalance[pk_e.X][pk_e.Y][token];
        //获取余额不能简单使用currentBalance[pk_e.X][pk_e.Y][token]吧，找了个方法，但是也不知道合不合适
        //acc[uint256(keccak256(abi.encodePacked(pk_e.X,pk_e.Y))).mod()] = sdctSystem.getBalanceCanSpentInternal(pk_e.X, pk_e.Y, token);
    }

    function unbind() public {
        delete bind[msg.sender];
    }

event printSituation(string str);
    //处理委托存款
    //cesc是转账方PGC地址向收款方PGC地址发起的交易内容密文
    //token唯一标识该交易内容
    //mu方便提币时的零知识证明
    function processEscrow(
        SDCTSystem.CT memory cesc,
        Proof_Escrow memory proofEscrow
    ) public payable {
        
        //1. 验证该托管交易在PGC中是否有效，未实现

        EscrowStatement memory statement;
        statement.cesc = cesc;
        statement.token = proofEscrow.token;
        statement.mu = proofEscrow.mu;

        //2. 验证token, 是否都在智能合约公开状态Epool中唯一，验证token形式的正确性，即使用schnorr
        //proof中的verifier验证用户确实知道token关于生成元f的离散对数
        require(!esc_token_pool[keccak256(abi.encode(proofEscrow.token))] 
        && !esc_mu_pool[keccak256(abi.encode(proofEscrow.mu))],"Duplicate parameter token or mu!!!" );
        require(verifyToken(proofEscrow.token,proofEscrow.R,proofEscrow.GBase, proofEscrow.z)==1, "Validation failed!!!");
        // require(verifyToken(proofEscrow.token,proofEscrow.R,proofEscrow.GBase, proofEscrow.z)==1, "Validation failed!!!");
        //3. 如果有效，便将托管交易 中的关键信息 和token， 放在公开的列表Epool中，即更新公开状态
        esc_pool.push(statement);
        esc_token_pool[keccak256(abi.encodePacked(proofEscrow.token.X, proofEscrow.token.Y))] = true;
        esc_mu_pool[keccak256(abi.encodePacked(proofEscrow.mu.X, proofEscrow.mu.Y))] = true;
        //emit printSituation("143 is ok!");
        //4. 扣除托管用户账户的余额
       {
        SDCTSystem.CT memory tmpUpdatedBalance = sdctSystem.getBalanceCanSpentInternal(
            proofEscrow.pk.X,
            proofEscrow.pk.Y,
            proofEscrow.tokenKind
        );
        //emit printSituation("151 is ok!");
        tmpUpdatedBalance.X = tmpUpdatedBalance.X.add(cesc.X.neg());
        tmpUpdatedBalance.Y = tmpUpdatedBalance.Y.add(cesc.Y.neg());
        //emit printSituation("154 is ok!");
        sdctSystem.rolloverAndUpdate(tmpUpdatedBalance, proofEscrow.pk.X, proofEscrow.pk.Y, proofEscrow.tokenKind);
       }
    }

    //验证Token
    //采用非交互的schnorr协议
    function verifyToken(
        BN128.G1Point memory token,//token当成PK公钥来看
        BN128.G1Point memory R, //r * G
        BN128.G1Point memory GBase,
        uint256 z //
        //uint256 c
    ) private returns(uint32) {
        //schnorr proof verifier
        uint256 c = uint256(keccak256(abi.encodePacked(token.X,token.Y, R.X, R.Y))).mod();
        BN128.G1Point memory g1 = GBase.mul(z.mod());
        g1.X = g1.X.mod();
        g1.Y = g1.Y.mod();
        BN128.G1Point memory g2 = token.mul(c).add(R);
        g2.X = g2.X.mod();
        g2.Y = g2.Y.mod();
        //emit VerifyTokenEvent(g1,g2);
        if(g1.eq(g2)) {
            return 1;
        } else {
            return 0;
        }
    }

    struct ProcessRedeemInput {
        SDCTSystem.CT cred; //是提币交易中处理后的密文，已经无法使用
        uint256 token;//表示该山寨币对应的真实币种
        BN128.G1Point pk;
        uint256 z1; //twisted EL验证使用
        uint256 z2;
        BN128.G1Point A;
        BN128.G1Point B;
        uint256 v;
        uint256 k;

    }

event PrintClist(BN128.G1Point[] clist1, BN128.G1Point[] clist2);
    function processRedeem(
        // SDCTSystem.CT memory cred, //是提币交易中的密文
        // uint256 token,//表示该山寨币对应的真实币种
        Verifier.SigmaProof memory proof_format,//密文格式正确性的证明
        Verifier.SigmaAuxiliaries memory aux_format,
        ProcessRedeemInput memory input
        // BN128.G1Point memory pk,
        // uint256 z1, //twisted EL验证使用
        // uint256 z2
    ) public payable {
         //1. 验证该提币请求是否有效，验证密文形式的正确性，参考PGC_p32_Fig.3
        // SDCTSystem.CT memory cred, TwEGProof memory proof_format
        uint32 flag1 = verifyFormat(input.cred, input);//验证密文格式是否有效
        require(flag1 == 1, "verifyFormat False!!!!");
        
        BN128.G1Point[] memory clist1 = new BN128.G1Point[](esc_pool.length);
        BN128.G1Point[] memory clist2 = new BN128.G1Point[](esc_pool.length);
        for (uint256 i = 0; i < esc_pool.length; i++) {
            clist1[i] = input.cred.X.add(esc_pool[i].cesc.X.add(esc_pool[i].mu).neg());
            clist2[i] = input.cred.Y.add(esc_pool[i].cesc.Y.neg());
        }
        
        require(Verifier.verifySigmaProof(clist1, clist2, proof_format, aux_format,input.pk), "verifySigmaProof MixSC line 228 False!!!");
        
        RedeemStatement memory statement;
        statement.cred = input.cred;
        red_pool.push(statement);
        
        Primitives.TwistedElgammalParams memory twElParams;
        SDCTSystem.CT memory cred;
        {
            twElParams.g = BN128.G1Point(sdctSetup.getG()[0],sdctSetup.getG()[1]);
            twElParams.h = BN128.G1Point(sdctSetup.getH()[0],sdctSetup.getH()[1]);
            twElParams.k = input.k;
            twElParams.v = input.v;
            twElParams.pk = input.pk;
        
            (cred.X, cred.Y) = Primitives.TwistedElgammal(twElParams);
        }

        sdctSystem.toBalanceOrPending(cred, input.pk.X, input.pk.Y, input.token);
        
    }


    function burnEth(
        address payable receiver,
        uint256 amount,
        uint256[2] memory publicKey
    ) public returns (bool) {
        return sdctSystem.burnETH(receiver, amount, publicKey);
    }


    //验证TwistedElGammal密文格式是否有效
    function verifyFormat(SDCTSystem.CT memory cred, ProcessRedeemInput memory input) public returns (uint32) {
        //验证成功返回1
        uint256 e = uint256(keccak256(abi.encode(input.A.X,input.A.Y, input.B.X, input.B.Y))).mod();
        BN128.G1Point memory tmp = input.pk.mul(input.z1);
        BN128.G1Point memory actual = cred.X.mul(e).add(input.A);
        if (!tmp.eq(actual)) {
            return 0;
        }
        BN128.G1Point memory g;
        g.X = sdctSetup.getG()[0];
        g.Y = sdctSetup.getG()[1];

        BN128.G1Point memory h;
        h.X = sdctSetup.getH()[0];
        h.Y = sdctSetup.getH()[1];
        
        tmp = g.mul(input.z1).add(h.mul(input.z2));
        actual = input.B.add(cred.Y.mul(e));
        if (!tmp.eq(actual)) {
            return 0;
        }
        return 1;
    }

    //管理员提走收取的手续费
    function transferFee() onlyOwner public {
        msg.sender.transfer(address(this).balance);
    }

}

