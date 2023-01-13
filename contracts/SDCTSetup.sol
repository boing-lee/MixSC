pragma solidity >= 0.5.0 < 0.6.0;
pragma experimental ABIEncoderV2;
import "./library/BN128.sol";

contract SDCTSetup {
  using BN128 for BN128.G1Point;
  using BN128 for uint;

  // g, h generator for sigma proof.
  // Warning: g is not the g base point of curve.
  BN128.G1Point public g;
  BN128.G1Point public h;

  // gBase represents curve base point on curve.
  BN128.G1Point public gBase;
  
  // bit size for vector.
  // value range [0, 2^bitSize-1]
  uint public constant bitSize = 32;
  // 2^n=bitSize; n is the number of ecpoints in innerproduct.
  uint public constant n = 5;
  // aggSize for agg range proof. must be pow of 2.
  uint public constant aggSize = 2;
  uint constant vectorSize = bitSize*aggSize;

  // fix point used in inner product.
  BN128.G1Point public u;

  // auth pk
  BN128.G1Point public pkauth;

  // 在实际使用时, 应该在创建合约时, 由外部系统直接传入. 保证隐私
  constructor(
    // uint256 pkx, 
    // uint256 pky
    ) public {
    // set h generator.
    // this should be the first step to set which will be used to
    // generate generator point.
    gBase.X = 1;
    gBase.Y = 2;

    // set auth pk.
    // pkauth.X = pkx;
    // pkauth.Y = pky;
    pkauth.X = 17055543450828620308172476622301403303189927854373814927021664153825542561100;
    pkauth.Y = 2436283105040896111218960252517862012802529129977374392539008377820407091577;


    g = generatePointByString("g generator of twisted elg");
    h = generatePointByString("h generator of twisted elg");
    u = generatePointByString("u generator of innerproduct");
  }

  // return g generator.
  function getG() public view returns(uint[2] memory) {
    uint[2] memory res;
    res[0] = g.X;
    res[1] = g.Y;
    return res;
  }

  // return h generator.
  function getH() public view returns(uint[2] memory) {
    uint[2] memory res;
    res[0] = h.X;
    res[1] = h.Y;
    return res;
  }

  // return u fix point.
  function getU() public view returns(uint[2] memory) {
    uint[2] memory res;
    res[0] = u.X;
    res[1] = u.Y;
    return res;
  }

  // return auth pk fix point.
  function getPK() public view returns(uint[2] memory) {
    uint[2] memory res;
    res[0] = pkauth.X;
    res[1] = pkauth.Y;
    return res;
  }

  // return bit size for value.
  function getBitSize() public pure returns(uint) {
    return bitSize;
  }

  // generatePointByString
  function generatePointByString(string memory s) internal view returns(BN128.G1Point memory) {
    uint scalar = uint(keccak256(abi.encodePacked(s))).mod();
    return gBase.mul(scalar);
  }

    // generatePointByString
  function generatePointByStringForTest(string memory s) public view returns(BN128.G1Point memory) {
    uint scalar = uint(keccak256(abi.encodePacked(s))).mod();
    return gBase.mul(scalar);
  }

}
