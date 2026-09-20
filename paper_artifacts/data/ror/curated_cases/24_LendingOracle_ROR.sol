// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ILendingCallback24 {
    function onCollateralExit24() external;
}

contract RORCollateralIndex24 {
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
        ILendingCallback24(msg.sender).onCollateralExit24();
        totalCollateral -= shares;
    }
}

contract RORBorrowMarket24 {
    RORCollateralIndex24 public immutable index;
    mapping(address => uint256) public debt;

    constructor(RORCollateralIndex24 index_) {
        index = index_;
    }

    function borrow(uint256 collateralShares) external {
        debt[msg.sender] += collateralShares * index.collateralIndex() * 75 / 100e18;
    }
}
