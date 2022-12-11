// SPDX-License-Identifier: MIT
pragma solidity >= 0.5.0 < 0.6.0;
pragma experimental ABIEncoderV2;
import "./library/BN128.sol";
import "./Primitives.sol";

library Verifier {
    using BN128 for BN128.G1Point;
    using BN128 for uint256;

    struct R1Proof {
        BN128.G1Point A;
        BN128.G1Point C;
        BN128.G1Point D;
        uint256[] f;
        uint256 zA;
        uint256 zC;
    }

    struct R1Auxiliaries {
        uint256 n;
        uint256 m;
        BN128.G1Point B_commit;
        BN128.G1Point g;
        BN128.G1Point[] h;
    }

    struct SigmaProof {
        BN128.G1Point B;
        R1Proof r1Proof;
        BN128.G1Point[] Gk1;
        BN128.G1Point[] Gk2;  //新添加，由于修改为TwEL加密返回两个椭圆曲线点，故需加一个GK2序列
        uint256 z;
    }

    struct SigmaAuxiliaries {
        uint256 n;
        uint256 m;
        BN128.G1Point g;
        BN128.G1Point[] h;
    }

    function verifyR1Proof(
        R1Proof memory proof,
        R1Auxiliaries memory aux,
        bool skip_final
    ) internal view returns (bool) {
        if (!skip_final) {
            BN128.G1Point[] memory group_elements = new BN128.G1Point[](4);
            group_elements[0] = proof.A;
            group_elements[1] = aux.B_commit;
            group_elements[2] = proof.C;
            group_elements[3] = proof.D;
            uint256 challenge_x = Primitives.generateChallenge(group_elements);
            uint256[] memory f_out = new uint256[](aux.n * aux.m);
            return verifyR1Final(proof, aux, challenge_x, f_out);
        }
        return true;
    }

    function verifyR1Final(
        R1Proof memory proof,
        R1Auxiliaries memory aux,
        uint256 challenge_x,
        uint256[] memory f_out
    ) internal view returns (bool) {
        for (uint256 j = 0; j < proof.f.length; j++) {
            if (proof.f[j] == challenge_x) return false;
        }
        uint256 cnt = 0;
        for (uint256 j = 0; j < aux.m; j++) {
            f_out[cnt] = 0;
            cnt++;
            uint256 tmp = 0;
            uint256 k = aux.n - 1;
            for (uint256 i = 0; i < k; i++) {
                tmp = tmp.add(proof.f[j * k + i]);
                f_out[cnt] = proof.f[j * k + i];
                cnt++;
            }
            f_out[j * aux.n] = challenge_x.sub(tmp);
        }

        BN128.G1Point memory one = Primitives.commitBits(
            aux.g,
            aux.h,
            f_out,
            proof.zA
        );

        BN128.G1Point memory cmp = aux.B_commit.mul(challenge_x).add(proof.A);
        if (!one.eq(cmp)) return false;

        uint256[] memory f_outprime = new uint256[](f_out.length);
        for (uint256 i = 0; i < f_out.length; i++) {
            f_outprime[i] = f_out[i].mul(challenge_x.sub(f_out[i]));
        }
        BN128.G1Point memory two = Primitives.commitBits(
            aux.g,
            aux.h,
            f_outprime,
            proof.zC
        );

        cmp = proof.C.mul(challenge_x).add(proof.D);
        if (!two.eq(cmp)) return false;

        return true;
    }

    function verifySigmaProof(
        BN128.G1Point[] memory commits1,
        BN128.G1Point[] memory commits2,
        SigmaProof memory proof,
        SigmaAuxiliaries memory aux,
        BN128.G1Point memory pk
    ) internal view returns (bool) {
        uint256 challenge_x;
        uint256 N = commits1.length;
        uint256[] memory f = new uint256[](N);
        {
            R1Auxiliaries memory r1aux;
            r1aux.n = aux.n;
            r1aux.m = aux.m;
            r1aux.B_commit = proof.B;
            r1aux.g = aux.g;
            r1aux.h = aux.h;
            if (!verifyR1Proof(proof.r1Proof, r1aux, true)) return false;

            BN128.G1Point[] memory group_elements = new BN128.G1Point[](
                proof.Gk1.length + 4
            );
            group_elements[0] = proof.r1Proof.A;
            group_elements[1] = proof.B;
            group_elements[2] = proof.r1Proof.C;
            group_elements[3] = proof.r1Proof.D;
            for (uint256 i = 0; i < proof.Gk1.length; i++) {
                group_elements[i + 4] = proof.Gk1[i];
            }
            challenge_x = Primitives.generateChallenge(group_elements);
            if (!verifyR1Final(proof.r1Proof, r1aux, challenge_x, f))
                return false;
        }

        //新添加代码块，主要为GK2,上边代码块为GK1
        {
            R1Auxiliaries memory r1aux;
            r1aux.n = aux.n;
            r1aux.m = aux.m;
            r1aux.B_commit = proof.B;
            r1aux.g = aux.g;
            r1aux.h = aux.h;
            if (!verifyR1Proof(proof.r1Proof, r1aux, true)) return false;

            BN128.G1Point[] memory group_elements = new BN128.G1Point[](
                proof.Gk2.length + 4
            );
            group_elements[0] = proof.r1Proof.A;
            group_elements[1] = proof.B;
            group_elements[2] = proof.r1Proof.C;
            group_elements[3] = proof.r1Proof.D;
            for (uint256 i = 0; i < proof.Gk2.length; i++) {
                group_elements[i + 4] = proof.Gk2[i];
            }
            challenge_x = Primitives.generateChallenge(group_elements);
            if (!verifyR1Final(proof.r1Proof, r1aux, challenge_x, f))
                return false;
        }

        uint256[] memory f_i_ = new uint256[](N);
        {
            for (uint256 i = 0; i < N; i++) {
                uint256[] memory I = Primitives.convertToNal(i, aux.n, aux.m);
                uint256 f_i = 1;
                for (uint256 j = 0; j < aux.m; j++) {
                    f_i = f_i.mul(f[j * aux.n + I[j]]);
                }
                f_i_[i] = f_i;
            }
        }

        //BN128.G1Point memory left1 = GenerateSigmaProofLeft(commits,aux,f_i_,proof.Gk1,challenge_x);
        

        // BN128.G1Point memory cmp = Primitives.commit(
        //     aux.g,
        //     0,
        //     aux.h[0],
        //     proof.z
        // );
        // struct SigmaProof {
        //     BN128.G1Point B;
        //     R1Proof r1Proof;
        //     BN128.G1Point[] Gk;
        //     uint256 z;
        // }
        BN128.G1Point[2] memory left;
        BN128.G1Point[2] memory cmp;
        
        (left[0], left[1]) = GenerateSigmaProofLeft(commits1, commits2, aux, f_i_, proof, challenge_x);

        (cmp[0], cmp[1]) = Primitives.TwistedElgammal(
            aux.g,
            aux.h[0],
            0,
            proof.z,
            pk
        );

        if (!left[0].eq(cmp[0]) || !(left[1].eq(cmp[1]))) return false;
        return true;
    }


    function GenerateSigmaProofLeft(
        BN128.G1Point[] memory commits1,
        BN128.G1Point[] memory commits2,
        SigmaAuxiliaries memory aux,
        uint256[] memory f_i_,
        SigmaProof memory proof,
        uint256 challenge_x
    ) internal view returns(BN128.G1Point memory, BN128.G1Point memory) {
        BN128.G1Point memory left1;
        {
            BN128.G1Point memory t1 = Primitives.multiExp(commits1, f_i_);
            BN128.G1Point memory t2 = BN128.zero();
            uint256 x_k = 1;
            for (uint256 k = 0; k < aux.m; k++) {
                t2 = t2.add(proof.Gk1[k].mul(x_k.neg()));
                x_k = x_k.mul(challenge_x);
            }
            left1 = t1.add(t2);
        }

         BN128.G1Point memory left2;
        {
            BN128.G1Point memory t3 = Primitives.multiExp(commits2, f_i_);
            BN128.G1Point memory t4 = BN128.zero();
            uint256 x_k = 1;
            for (uint256 k = 0; k < aux.m; k++) {
                t4 = t4.add(proof.Gk2[k].mul(x_k.neg()));
                x_k = x_k.mul(challenge_x);
            }
            left2 = t3.add(t4);
        }
        return (left1, left2);
    }

}
