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
        vk.alpha = Pairing.G1Point(uint256(0x27fc2868bf9061a9e9b9fb7a35e78e6ba63d07a23edd319cd7a423f44bb60ba1), uint256(0x150917011f87d8e7b0642e33cdf13884332ea9e6ecee7393d3a91657d30bd7b3));
        vk.beta = Pairing.G2Point([uint256(0x1eb327d37d29617334518f09323f5ddb9f86970b347c131c01653011f80d22fc), uint256(0x00edc1c4d4b3d3062c221a12dc531d80c4de55df622508022c848d3920de4d4e)], [uint256(0x18cc69e586526f18dacbfa786be649a3f1d6fd9a3c834fea0b9d3cf82e0b5fcd), uint256(0x11ee8c3388375eefaeed33cabaeccb63df03ac44f0c5d94b5c8fb20c7c69191b)]);
        vk.gamma = Pairing.G2Point([uint256(0x0d2c1c54419df1fd9d3db7acbcbfc9817bf2846c22185ba3b1e9a0a1ca19b069), uint256(0x053f1b727dfd218765a61f343f979d842a82c571c0c21e0eebb60bfc1da41fc4)], [uint256(0x12d450d6f5b60ab3d5bbacfe516bc8dc44a5dd25d7e77049459b7579141993e9), uint256(0x2c9c6889851cf80c2fa6f6452ba749fb8553bf7dc02b0ea8fe087e59368f9a07)]);
        vk.delta = Pairing.G2Point([uint256(0x022361c1ff597108628b4ba6a2156bae124eac2f6ce30a5ee448acc7f38b5fc2), uint256(0x13965fba444acfcf8848112af9e55b5104ce7af511e90a7753eee8f3a9faed15)], [uint256(0x22590cd6203f0c8fa1e201cd7ef22852e5a36855bc710c2684d429076521686a), uint256(0x05391a2a59107666c8a961eb4f8a4f2a90008aa284184e2f38b3aaadf384ae6a)]);
        vk.gamma_abc = new Pairing.G1Point[](10);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x03723556533edf868088dafdec020ba7c5ce4b6215672cc9b5ef6fbac3123999), uint256(0x303cfbe41020f9ea33130265071fdd330fdac9a6809a935994529d9adf5b7c38));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x20758f51e1929789aeae6b90adb0e3dfedcc01015d14424bb920504ebe351be6), uint256(0x2b7cb020b6925fe7795ff595f3e16bf1d36b2358d7412035fd4fc83f21bac057));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2947143b7ab3154003322fdfce55213afd56cdd2774847c320f27c6b33c2bcba), uint256(0x26b2b6d7d33ce5f94ca471b4f8a9e03d7eec0ffb509eb30c2c4f7baa4e4097a7));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x04bcf730fdf66d86421f1a1e554714aa458cf7bc46a45449076f553fad327b36), uint256(0x07f3b15f2793f8f7bf60ae4e48dd0827477182f319d1ca79ce471923e71d0a77));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x26bc436f0c707a36d2872888dcef16b6fe61174647a54a11248d4b6716d927f2), uint256(0x026289b9dd80edb155553d1919e4e2abce236f9edadc923bfab72e6d0f241fd4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0307880bc880c3684c60040166702907d09b8e05487360011786d9b98280daff), uint256(0x197ea7217ae85f679276f20c238be0b07c8e4f0581ee8546e78cb10a7dc7d74b));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1aee810f0be5c02a022cf6bb211a943f184d291392138491e765cbfed4d2d737), uint256(0x2df1e137c9aa98fcc0848b782017cc659d469412889c243d0c8c0392138be856));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1499d63f133e664cbb518c5220e85ac758a2711160abc71c82e11d1e864a6950), uint256(0x2c6834e8c4733d2cae74062a474ed5e25432e2c00dc094013337cfd65301e34e));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1830e860752e820e279b77aab29dbed2e3d1337968dab7f5b01a459446c86022), uint256(0x1a83a1fad15716e8852f5861c2acee6b40985e4801d14edb018d8231c1cf90bc));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x146b3899ec007533905e8951a4edcd34dd95ba6158865e23fc2f5f5f93b51264), uint256(0x0540b1bbdf244385695e54016c082861c830cc0c9929e017f5d13c9f8e712a5e));
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
