// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAMMCallback30 {
    function onSwap30() external;
}

contract RORSpotPriceAMM30 {
    uint256 public reserveIn;
    uint256 public reserveOut;

    function seed(uint256 inReserve, uint256 outReserve) external {
        reserveIn = inReserve;
        reserveOut = outReserve;
    }

    function spotPrice() external view returns (uint256) {
        return reserveIn * 1e18 / reserveOut;
    }

    function swapOut(uint256 amountOut) external {
        IAMMCallback30(msg.sender).onSwap30();
        reserveOut -= amountOut;
    }
}

contract RORSpotPriceVault30 {
    RORSpotPriceAMM30 public immutable amm;
    mapping(address => uint256) public minted;

    constructor(RORSpotPriceAMM30 amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        minted[msg.sender] += lpAmount * amm.spotPrice() / 1e18;
    }
}
