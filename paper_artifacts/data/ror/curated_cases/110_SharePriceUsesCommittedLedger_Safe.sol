// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface LedgerHook110 {
    function afterLedgerCommit() external;
}

contract SharePriceUsesCommittedLedgerSafe110 {
    uint256 public committedAssets;
    uint256 public committedShares;
    LedgerHook110 public hook;

    constructor(LedgerHook110 hook_) {
        hook = hook_;
    }

    function commitLedger(uint256 assets, uint256 shares) external {
        committedAssets = assets;
        committedShares = shares;
        hook.afterLedgerCommit();
    }

    function sharePrice() external view returns (uint256) {
        return committedShares == 0 ? 1e18 : (committedAssets * 1e18) / committedShares;
    }
}
