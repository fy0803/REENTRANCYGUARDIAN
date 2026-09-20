// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAMMCallback40 {
    function onSwap40() external;
}

contract RORSpotPriceAMM40 {
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
        IAMMCallback40(msg.sender).onSwap40();
        reserveOut -= amountOut;
    }
}

contract RORSpotPriceVault40 {
    RORSpotPriceAMM40 public immutable amm;
    mapping(address => uint256) public minted;

    constructor(RORSpotPriceAMM40 amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        minted[msg.sender] += lpAmount * amm.spotPrice() / 1e18;
    }
}
