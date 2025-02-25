// SPDX-License-Identifier: MIT
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract VerifierRange {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x20abae0b5118678fbec24b4831f9142775d4e3ba83db99abd5881e09b25f0e4a), uint256(0x167edfca4b1e012cd0a4cbda3ab3afe53574846fb0bab69116c3a6bfee284542));
        vk.beta = Pairing.G2Point([uint256(0x117d37c3eacb031a10816de86e374ff212ec307f9f84158e7b2cda3b1c244e29), uint256(0x2c5981f8ed95b6ddd48c16c17ab68e8199e4d30f3f6c34017069ae2d1b99383a)], [uint256(0x04b9889f87e05028d0bffbc331f9e0de98e00baca8b9bea576fce08f46aec043), uint256(0x2b77cf0a56cf334933e38c72c235a4aeeab0b42561f978ddeb8c4d70024df0b9)]);
        vk.gamma = Pairing.G2Point([uint256(0x16961071290fbece1e04077a383800577fef02116b2625018fcb6d0d7e420bb7), uint256(0x2a88a0757ea170ada850378e0a6372ad94cda322b0d51290ef85e0a3cbf0e0fd)], [uint256(0x2fb3119d134b3663c977131856a34f99a1989e7643078f3429297c6cd4658acf), uint256(0x2853864b29c7a554aeb4cc918eab8da6fa93824df4cd2a8af89cf4ee21ebf462)]);
        vk.delta = Pairing.G2Point([uint256(0x17c8aa54ed872f6d049f60ec59de6cd5fc635545c42350e4e83478a6ec411fbf), uint256(0x09044e475a16e5b6e3501e909b2de95f9bcceb8081865e0f54a15a68cf041b55)], [uint256(0x07287625b8680114914075388af77195bf0b0feac7a08500082e2d86a5523dce), uint256(0x255be191c005d58ea75c5f0e9c13fbeee3a8f765598e20377d934afe4ab54d97)]);
        vk.gamma_abc = new Pairing.G1Point[](2);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x289cd284e0c6668fbe9ea3cab502b18d2403585ab5ec1e5abf7fcac7ba3a62bf), uint256(0x212bcf2e71f0b7c80bfa8b424ddcc23c3e16ecb5f37da3055282e640a731cafe));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2609f9e9fc9c417525e2ea3a96ae8807345445e5eeb77de0c6942c7c5baed1a4), uint256(0x1bccf47c90d59cc43c6f7505dfa13ea94fbf12dd37e2410039ece445d6373b15));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[1] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](1);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}

contract VerifierCompare {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x07fdd7b5d62cb2cfa50dd5a48ad4368a83a5fc3baf4d0c24e15d3b02ee4cdba7), uint256(0x1c58924c455bb477db5c79458639cc2ee31bc2efb01d5a677857a732e8863b26));
        vk.beta = Pairing.G2Point([uint256(0x09622310fa34e4350067ccb945ea051d3b3cdf4d1dd948103ef4fe86f77439ba), uint256(0x17cba59541aefbf9d8c1055c00a6bf90b1372ef84c55d5018efe7e26532c7a6b)], [uint256(0x0c8b7ba26bea7d73ad61a127f1ff4d896841bf3827cc10d51b4453d6a0448d62), uint256(0x236616aa03e440a6780de38fcd88ac43a306cd1f85d4616021304e67ea9ef715)]);
        vk.gamma = Pairing.G2Point([uint256(0x2e3ba5196778544e054efaa63c9e508a6b1e445fb2f84140f998a33c21673771), uint256(0x244b894408adf7d43dea5921299d7561b847f4b1dffd70851092a3bf43aea9ff)], [uint256(0x012c7ba660539cfee597b9642d315fbf7e26e39466d96e75fc74b63ad917ec6f), uint256(0x17f09bc3f74c9274b8b50bb1386029586b97f861771d699ae247033669ec803a)]);
        vk.delta = Pairing.G2Point([uint256(0x2d66e9c1db84ca0ffd769f9a05582f2292b77254079e682861b0a8d6a5c4ad36), uint256(0x03d17c79de4406c61402f3cfd7d05b67fe0b39afa64d06d69f8ce264cb7632fc)], [uint256(0x2d8359434f56f0df921f9acc0eeafe35d9fd2ec755ae9535bfdd23d80ea79126), uint256(0x23aeb16354fdc5d34adaaee515569e36342e899d74465b33c8b21fe888fa9d81)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x05085b8725179707f11f0e70a24abe017ba25fafcf88c58ffe05b029f620ced8), uint256(0x050a4f197ecb1e8291a1d1f2993ad7f48d21f306a176ea35fcf5f576984ecda8));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2a98f6282c57cbf8c0bdafe79e094a3f44ca70cf68c576cf689a956289740bda), uint256(0x20720521cf09cecb8a85bcfcc0266f2b026a4a80877efbe18d992706b9e9a677));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1acb80c2188896521ac65777d093eb518ef2993868e249bcf0a09781aed75c0f), uint256(0x1f42c15f43b1010a953831d04078092e9653e8534d6cb90c8755f2977030a3da));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0139fd65beffc6830280518a201c77c7dd6d61ed18bea52b9a0310acabd7a11d), uint256(0x0b0c0cb4bfab120e5a179f3070e13da498650b82b67a12cf6ff9922fb4ba2dab));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2bf11d7d4d04ed4b91a9a83861baff1b002bf94b9756e2a8f76f462496a6bfe7), uint256(0x118796256f9da3e70d9daf551b1c5277c811f7cd1918f8f82f88ac18607cd244));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1a1fe831e59070b3ba6a56c02b9fdb985ed41c92ad79d9ae4badbab5cc05e586), uint256(0x08f11b229f9f5f369e794777180ac3db2af08ef14bfef94c4204d3c9f1581d14));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2df99224e9e5248ad999053e128a44971f3de9667944ef1205daaadeec4fb182), uint256(0x07f4b7d29c53fe68e3195d3c2d5c607e8dcaac09d2c7e9dc1a9279c59a75f65f));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x05e6b6eb0b9fae13de5d0ecc7ff5bbe7b68927033f9834de0b2c7c6fd6115061), uint256(0x04005fd296006a9373158d5d95405ac216c17ef07de9c4bbb9fb1741260bbfa7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0bdea187f8eece58508da3bde56a2c099920d85ced06206332d787cec329581b), uint256(0x1e1eb43c0e7145ef3a34d7b819d44c2cdbe847629552d23dba15a482b6979488));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2e005ee667e8042b237f112d477cb0b295ec6542cf95e0ff5219c48b8f16fb38), uint256(0x053c0cb7d2da99628205890839aed8aabca5354dc9d1a6e58b95fee73e38f08a));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[9] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](9);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
