// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICollateralHook14 {
    function onExitPending14(address owner, uint256 amount) external;
}

contract RORCollateralIndex14 {
    RORCollateralLedger14 public immutable ledger;

    constructor(RORCollateralLedger14 ledger_) {
        ledger = ledger_;
    }

    function seed(address user, uint256 amount) external {
        ledger.seed(user, amount);
    }

    function collateralIndex() external view returns (uint256) {
        return ledger.collateralIndex();
    }

    function exit(uint256 shares, ICollateralHook14 hook) external {
        uint256 amount = ledger.stageExit(msg.sender, shares);
        hook.onExitPending14(msg.sender, amount);
        ledger.settleExit(msg.sender, shares, amount);
    }
}

contract RORCollateralLedger14 {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public pendingExit;
    uint256 public totalCollateral;
    uint256 public totalShares;
    uint256 public pendingCollateral;

    function seed(address user, uint256 amount) external {
        collateral[user] = amount;
        totalCollateral = amount;
        totalShares = amount;
    }

    function collateralIndex() external view returns (uint256) {
        return (totalCollateral - pendingCollateral) * 1e18 / totalShares;
    }

    function stageExit(address owner, uint256 shares) external returns (uint256 amount) {
        uint256 amount = shares * totalCollateral / totalShares;
        pendingExit[owner] += amount;
        pendingCollateral += amount;
        return amount;
    }

    function settleExit(address owner, uint256 shares, uint256 amount) external {
        pendingExit[owner] -= amount;
        pendingCollateral -= amount;
        collateral[owner] -= shares;
        totalShares -= shares;
        totalCollateral -= amount;
    }
}

contract RORBorrowMarket14 {
    RORCollateralIndex14 public immutable index;
    mapping(address => uint256) public debt;

    constructor(RORCollateralIndex14 index_) {
        index = index_;
    }

    function borrow(uint256 collateralShares) external {
        debt[msg.sender] += collateralShares * index.collateralIndex() * 75 / 100e18;
    }
}
