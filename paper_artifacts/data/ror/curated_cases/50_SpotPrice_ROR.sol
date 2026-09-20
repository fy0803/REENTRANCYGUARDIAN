// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAMMCallback50 {
    function onSwap50() external;
}

contract RORSpotPriceAMM50 {
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
        IAMMCallback50(msg.sender).onSwap50();
        reserveOut -= amountOut;
    }
}

contract RORSpotPriceVault50 {
    RORSpotPriceAMM50 public immutable amm;
    mapping(address => uint256) public minted;

    constructor(RORSpotPriceAMM50 amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        minted[msg.sender] += lpAmount * amm.spotPrice() / 1e18;
    }
}
