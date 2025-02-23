// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./verifier.sol";

contract Auction_Compare {
    struct Bid {
        string encrypt_bid;
        uint256[2] hash_bid;
    }

    uint256 public highestBid;
    uint256[2] public highestHash;

    mapping (address => Bid) public bids;
    address[] public bidders;
    string public public_key;
    uint32 public min_bid;
    VerifierRange public verifierRange;
    VerifierCompare public verifierCompare;

    constructor(address _verifierRange, address _verifierCompare) {
        verifierRange = VerifierRange(_verifierRange);
        verifierCompare = VerifierCompare(_verifierCompare);
    }

    function startAuction(string memory _public_key, uint32 _min_bid) public {
        public_key = _public_key;
        min_bid = _min_bid;
    }

    function bidding(string memory _encrypt_bid, uint256[2] memory _hash_bid, VerifierRange.Proof memory proof, uint[1] memory input) public {
        require(verifierRange.verifyTx(proof, input), "nono");
        Bid memory bid = Bid({
            encrypt_bid: _encrypt_bid,
            hash_bid: _hash_bid
        });
        bids[msg.sender] = bid; 
        bidders.push(msg.sender);
    }

    function endAuction(VerifierCompare.Proof memory proof, uint[9] memory input) public{
        bool isValid = verifierCompare.verifyTx(proof, input);
        // address winner;

        if (isValid) {
            highestBid =  input[6]; 
            highestHash = [input[7], input[8]];
        }

        // for(uint i = 0;i < bidders.length;i++){
        //     if (bids[])
        // }
        
    }
}