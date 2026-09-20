// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILendingCallback34 {
    function onCollateralExit34() external;
}

contract RORCollateralIndex34 {
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
        ILendingCallback34(msg.sender).onCollateralExit34();
        totalCollateral -= shares;
    }
}

contract RORBorrowMarket34 {
    RORCollateralIndex34 public immutable index;
    mapping(address => uint256) public debt;

    constructor(RORCollateralIndex34 index_) {
        index = index_;
    }

    function borrow(uint256 collateralShares) external {
        debt[msg.sender] += collateralShares * index.collateralIndex() * 75 / 100e18;
    }
}
