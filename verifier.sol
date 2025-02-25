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
        vk.alpha = Pairing.G1Point(uint256(0x157efcbe78ac8a440e6e81026b20e84396ea2de8c1f021a6602b8e9716eed9a9), uint256(0x29fc6fe7a56b4562b08f54743b241430298b7a6530bc5c4c1f14b67d2331f3b3));
        vk.beta = Pairing.G2Point([uint256(0x199230de888cebb89a4b48a117a34edf44d5e0171ee31ad17ad3b1af41d79dcc), uint256(0x23511e29ef20f5b813109857f276e3790c81af2476fddab083e6593a71a41897)], [uint256(0x2eca169bfae8f31b8e6b6616c432ecb6bb39cbb9d0ae3b63d4f1c3efd853cff7), uint256(0x0e3b5c35514af78db27a66e3616f8717a395fc01ba88ced3b80d1215e6bf2ce5)]);
        vk.gamma = Pairing.G2Point([uint256(0x0cf6d3f844babe4b835ea2b06f808ad1699fa1f610e52af7a6ad349bb84877fc), uint256(0x0a0f78356856f2064a4bceaf33289156decb98f1bc69101cd68d75ff453f6b7f)], [uint256(0x217eb8adf7ece8ba448145ecab0bd3d21bfb45f2995c9b088064556f92fcbd80), uint256(0x22a7533990a63f4d1a66abd6d899846d174d483ef1ea46c27012eee53362fd24)]);
        vk.delta = Pairing.G2Point([uint256(0x035396e8388937fe2cc318e5be6950dea258335356fb466cf961e6974cddc79c), uint256(0x2098e2fce3a69532937e045d428ea4d9259b9c1695669a90d53bbff3ba166c45)], [uint256(0x116873d16cfa9205f2f8ec552e2aa5afcc16ec4fd6abc3a3d8efc24755944131), uint256(0x270dcefab281c03a6cbf49a07c5c139c462ae35b39fdd679fe86ed02d1b0a0d1)]);
        vk.gamma_abc = new Pairing.G1Point[](11);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2cd2eac2c8ed893d5f39bbeaa2b6c8162221a27088377bdd3eec85535d4eced9), uint256(0x24385745e1172fdab47abee657b8662a5d2d5229f1fbbb2494e212b23bd406c5));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1c78dff75691d080cc0828d4970ae4cfab3c1c0183721489e57788602401f7c2), uint256(0x291fb6a10e3ef745630206baa842303d7ec03bd9339ec6effd7df253a240aa72));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x21f7afc2fc1fce4a5956f4b5631da1a24e9b278fbb8c621e204de047c7154237), uint256(0x08628afb48647d2413b97a331feb99df897bee02e3e274f94edff1ad5446e7bf));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x199de0a010aa8ea2b75f14a133a2dd029a088e48f7f4d2111429a42dc72b06ec), uint256(0x12bc87613f7007a6579ab3b163a35d11071598280b813219c482414fd1ec620f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2205cb2b5598bc17c0bbbd865782a88719b7801bb524ccaec61d4725b458f7cc), uint256(0x23b823c39c455f495987fd49ff8b35da3093a2c380b5d83f82d72beab3964632));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x248e3717cf9919518eccac1f09f349aab6567539b96e9ecd33a14cca65bd0f7b), uint256(0x17175474047f40e2cc3a16a10877b6bf2f9caf79f3defaa0f679aa91c5bd4572));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x052b5d0832bb09f4eceecd120afe22494bde93632ccbd7e8b723ea1437556158), uint256(0x18a06d81b06010d021771d5533421854e36fa61461d8e87aed6f7f22ce664208));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09431d3aaaad4de6bb7bb1ef58a12d7c41d7c80b0733f0f662bc47f57253cfb7), uint256(0x22cb66319d08535cf775ffb39f65140ac9ec9b4946f81ed2ce48fbef232e7cdb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x20cddaf9c25b71daf8e7c14527d66a82fc22a757425426da22e9757d8c4c3423), uint256(0x02a57ea004502893b99426148267955d0e29b1603f3974e8ef0e93bdcc0f6be9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0b7a92415540b620129313a145a955c4615dcd0e9122129460b36911cdd20f4e), uint256(0x1449737a459e3f44b0e81f22c9430c7a1f4cd84bb91400106a43663992002ebb));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1b5a67282c06b2d931d4a04a743b71ee5a4b1b92d0e23bc17caaeb81fa519c4a), uint256(0x187030fca071d7e30def8f9f41440e47af91452b48cc0c516b5065968652b236));
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
            Proof memory proof, uint[10] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](10);
        
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
