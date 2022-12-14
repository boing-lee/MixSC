pragma solidity >= 0.5.0 < 0.6.0;
pragma experimental ABIEncoderV2;

import "./library/BN128.sol";

library Primitives {
    using BN128 for BN128.G1Point;
    using BN128 for uint256;

    struct TwistedElgammalParams {
        BN128.G1Point g;
        BN128.G1Point h;
        uint256 k;
        uint256 v;
        BN128.G1Point pk;
    }

    // function commit(
    //     BN128.G1Point memory g,
    //     uint256 v,
    //     BN128.G1Point memory h,
    //     uint256 r
    // ) internal view returns (BN128.G1Point memory) {
    //     if (v == 0) return h.mul(r);
    //     if (r == 0) return g.mul(v);
    //     return g.mul(v).add(h.mul(r));
    // }

//---------------------------------TwistedElgammal加密(用于替换上方的commit)-----------------------------------------
    function TwistedElgammal(
        // BN128.G1Point memory g,//不要忘记可以在SDCTSetup中拿取，应该不需要传参了
        // BN128.G1Point memory h,//不要忘记可以在SDCTSetup中拿取，应该不需要传参了
        // uint256 r,//随机数
        // uint256 m,//明文
        // BN128.G1Point memory pk//公钥
        TwistedElgammalParams memory twElParams
    ) public view returns (BN128.G1Point memory, BN128.G1Point memory) {
        // BN128.G1Point memory A = pk.mul(a);
        // BN128.G1Point memory tmp = g.mul(a);
        // BN128.G1Point memory B = tmp.add(h.mul(b));
        // uint256 e = uint256(keccak256(abi.encode(A, B))).mod();
        // uint256 z1 = a.add(e.mul(r));
        // uint256 z2 = b.add(e.mul(v));
        // return (A,B,z1,z2);

        BN128.G1Point memory X = twElParams.pk.mul(twElParams.k);
        BN128.G1Point memory Y = twElParams.g.mul(twElParams.k).add(twElParams.h.mul(twElParams.v));
        return (X, Y);

    }


    function multiExp(BN128.G1Point[] memory hs, uint256[] memory exps)
        internal
        view
        returns (BN128.G1Point memory)
    {
        BN128.G1Point memory res = BN128.zero();
        for (uint256 index = 0; index < hs.length; index++) {
            BN128.G1Point memory tmp = hs[index].mul(exps[index]);
            res = res.add(tmp);
        }
        return res;
    }

    function commitBits(
        BN128.G1Point memory g,
        BN128.G1Point[] memory hs,
        uint256[] memory exps,
        uint256 r
    ) internal view returns (BN128.G1Point memory) {
        BN128.G1Point memory tmp1 = multiExp(hs, exps);
        BN128.G1Point memory tmp2 = g.mul(r);
        BN128.G1Point memory res = tmp1.add(tmp2);
        return res;
    }

    function generateChallenge(BN128.G1Point[] memory group_elements)
        internal
        pure
        returns (uint256)
    {
        bytes memory encoding = abi.encode(group_elements);

        return uint256(sha256(encoding));
    }

    function convertToNal(
        uint256 num,
        uint256 n,
        uint256 m
    ) internal pure returns (uint256[] memory) {
        uint256[] memory out = new uint256[](m);
        uint256 j = 0;
        while (num != 0) {
            uint256 rem = num % n;
            num = num / n;
            out[j] = rem;
            j++;
        }
        return out;
    }
}
