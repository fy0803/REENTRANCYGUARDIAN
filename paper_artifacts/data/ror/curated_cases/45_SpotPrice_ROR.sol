// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAMMCallback45 {
    function onSwap45() external;
}

contract RORSpotPriceAMM45 {
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
        IAMMCallback45(msg.sender).onSwap45();
        reserveOut -= amountOut;
    }
}

contract RORSpotPriceVault45 {
    RORSpotPriceAMM45 public immutable amm;
    mapping(address => uint256) public minted;

    constructor(RORSpotPriceAMM45 amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        minted[msg.sender] += lpAmount * amm.spotPrice() / 1e18;
    }
}
