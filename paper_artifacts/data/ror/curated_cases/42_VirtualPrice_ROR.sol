// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVirtualPriceCallback42 {
    function onRemoveLiquidity42() external;
}

contract RORCurvePool42 {
    mapping(address => uint256) public lpBalance;
    uint256 public totalSupply;
    uint256 public balanceA;
    uint256 public balanceB;

    function seed(address user, uint256 lp, uint256 a, uint256 b) external {
        lpBalance[user] = lp;
        totalSupply = lp;
        balanceA = a;
        balanceB = b;
    }

    function get_virtual_price() external view returns (uint256) {
        return (balanceA + balanceB) * 1e18 / totalSupply;
    }

    function removeLiquidity(uint256 lpAmount) external {
        lpBalance[msg.sender] -= lpAmount;
        totalSupply -= lpAmount;
        IVirtualPriceCallback42(msg.sender).onRemoveLiquidity42();
        balanceA -= lpAmount;
        balanceB -= lpAmount;
    }
}

contract RORCurveBorrowMarket42 {
    RORCurvePool42 public immutable pool;
    mapping(address => uint256) public minted;

    constructor(RORCurvePool42 pool_) {
        pool = pool_;
    }

    function mint(uint256 lpCollateral) external {
        minted[msg.sender] += lpCollateral * pool.get_virtual_price() / 2e18;
    }
}
