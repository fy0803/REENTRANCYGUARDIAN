// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRedeemSettlement56 {
    function settleRedeem56(address owner, uint256 assets, uint256 rate) external;
}

contract TotalAssetsCommit56 {
    struct RedeemRequest {
        uint256 assets;
        uint256 rate;
        uint256 epoch;
    }

    mapping(address => RedeemRequest) public requests;
    uint256 public totalSupply = 1_000 ether;
    uint256 public totalAssetsCache = 1_000 ether;
    uint256 public pendingRedeems;
    uint256 public exchangeRateCache = 1e18;
    uint256 public epoch;
    bool public withdrawalsOpen = true;

    event RedeemQueued(address indexed owner, uint256 assets, uint256 rate, uint256 epoch);

    function exchangeRate() external view returns (uint256) {
        return exchangeRateCache;
    }

    function previewShares(uint256 assets) external view returns (uint256) {
        return assets * 1e18 / exchangeRateCache;
    }

    function setWithdrawalsOpen(bool open) external {
        withdrawalsOpen = open;
    }

    function queueRedeem(uint256 assetsOut, address settlement) external {
        require(withdrawalsOpen, "CLOSED");
        require(assetsOut > 0 && assetsOut <= totalAssetsCache / 2, "BAD_ASSETS");

        epoch += 1;
        totalAssetsCache -= assetsOut;
        pendingRedeems += assetsOut;
        exchangeRateCache = totalAssetsCache * 1e18 / totalSupply;
        requests[msg.sender] = RedeemRequest(assetsOut, exchangeRateCache, epoch);

        emit RedeemQueued(msg.sender, assetsOut, exchangeRateCache, epoch);
        IRedeemSettlement56(settlement).settleRedeem56(msg.sender, assetsOut, exchangeRateCache);
    }
}

