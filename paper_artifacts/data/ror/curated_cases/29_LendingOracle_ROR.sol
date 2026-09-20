// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILendingCallback29 {
    function onCollateralExit29() external;
}

contract RORCollateralIndex29 {
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

    function exit(uint256 shares) external {
        collateral[msg.sender] -= shares;
        totalShares -= shares;
        ILendingCallback29(msg.sender).onCollateralExit29();
        totalCollateral -= shares;
    }
}

contract RORBorrowMarket29 {
    RORCollateralIndex29 public immutable index;
    mapping(address => uint256) public debt;

    constructor(RORCollateralIndex29 index_) {
        index = index_;
    }

    function borrow(uint256 collateralShares) external {
        debt[msg.sender] += collateralShares * index.collateralIndex() * 75 / 100e18;
    }
}
