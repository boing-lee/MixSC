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

        return uint256(sha256(encoding)).mod();
    }

    function convertToNal(
        uint256 num,
        uint256 n,
        uint256 m
    ) public pure returns (uint256[] memory) {
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

// l<2^m, 求m
    function getMi(uint256 l) public view returns (uint256){
        uint256 i=0;
        uint256 base = 2;
        while(true){
            if(l < base.modExp(i))
                return i;
            i++;
        }
    }

    //获取m行2列的delta矩阵, 用一维数组表示，其中第i行第j列元素为delta[2*i+j]
    function getDelta(uint256[] memory l_bin, uint256 m) internal pure returns (uint256[] memory) {
        uint256[] memory delta = new uint256[](2*m);
        for(uint256 i=0; i<m;i++){
            if(l_bin[i]==0){
                delta[2*i]=1;
                delta[2*i+1]=0;
            }
            else{
                delta[2*i]=0;
                delta[2*i+1]=1;
            }
        }
        return delta;
    }

    //获取m行2列的随机数a矩阵, 用一维数组表示，其中第i行第j列元素为a_m[2*i+j]
    function getMatricesA(uint256 m) internal view returns (uint256[] memory) {
        uint256[] memory a_m = new uint256[](2*m);
        for(uint256 i=0; i<m;i++){
            a_m[2*i] = uint(keccak256(abi.encodePacked(block.timestamp, i))).mod();
            a_m[2*i+1] = uint(keccak256(abi.encodePacked(i, block.timestamp))).mod();
        }
        return a_m;
    }

    //两个多项式s1、s2相乘，index1为s1的最高次，index2为s2的最高次
    //s1的元素s1[i]表示x^i的系数，s2也相同
    function TwoPolyMul(uint256[] memory s1, uint256 index1, uint256[] memory s2, uint256 index2) public pure returns (uint256[] memory,uint256){
        uint256[] memory tmp = new uint256[](index1+1);
        uint256 index=index1;
        for(uint256 i=0;i<index2;i++){
            for(uint256 j=0;j<index1;j++){
                tmp[i+j]=s1[j].mul(s2[i]).add(tmp[i+j]);
                if(i+j+1>index1)
                    index=i+j+1;
            }
        }
        return (tmp,index);
    }

    //m表示一次项的数量，s每两个元素表示一个多项式
    //即s[0]表示第一个多项式的常数项系数，s[1]表示第一个多项式的一次项系数；s[2]表示第二个多项式的常数项系数……
    function PolyMul(uint256 m,uint256[] memory s) internal pure returns (uint256[] memory){
        uint256[] memory s1 = new uint256[](m+1);
        uint256[] memory s2 = new uint256[](2);
        uint256 index=2;
        uint256 k=1;
        s1[0]=s[0];
        s1[1]=s[1];
        while(k<m){
            s2[0]=s[2*k];
            s2[1]=s[2*k+1];
            (s1,index) = TwoPolyMul(s1,index,s2,2);
            k++;
        }
        return s1;
    }

    //获取P_i
    //得到的是一个m项的多项式连加
    //P_i[k]表示x^k的系数，即协议中的P_i,k
    function getP(uint256 i, uint256[] memory delta, uint256[] memory a_m, uint256 m) internal pure returns (uint256[] memory){
        uint256[] memory i_bin =convertToNal(i,2,m);
        uint256[] memory s=new uint256[](2*m);
        for(uint256 j=0;j<m;j++){
            s[2*j]=a_m[j*2+i_bin[j]];
            s[2*j+1]=delta[j*2+i_bin[j]];
        }
        return PolyMul(m,s);
    }


    //封装好的获取P_i的函数
    //只需提供l和i即可
    function GetP(uint256 l, uint256 i, uint m, uint256[] memory a) public view returns (uint256[] memory){
        // require(l>=i,"i must less than or equal to l");
        // return getP(i,getDelta(convertToNal(l,2,m),m),getMatricesA(m),m); //需要修改为之前使用的固定的a[]
        return getP(i,getDelta(convertToNal(l,2,m),m), a,m);
    }



    //获取m行2列的随机数hs矩阵, 用一维数组表示，其中第i行第j列元素为hs[2*i+j]
    function geths(uint256 m, uint256 n,  BN128.G1Point memory g) internal view returns (BN128.G1Point[] memory) {
        BN128.G1Point[] memory hs = new BN128.G1Point[](n*m);
        for(uint256 i=0; i<m;i++){
            hs[2*i] = g.mul(uint(keccak256(abi.encodePacked(block.timestamp, i, m))).mod());
            hs[2*i+1] = g.mul(uint(keccak256(abi.encodePacked(i, block.timestamp, m))).mod());
        }
        return hs;
    }


}
