// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IExitObserver12 {
    function onExitQueued12(address owner, uint256 assets) external;
}

contract RORCurvePool12 {
    RORCurveLedger12 public immutable ledger;

    constructor(RORCurveLedger12 ledger_) {
        ledger = ledger_;
    }

    function seed(address user, uint256 lp, uint256 a, uint256 b) external {
        ledger.seed(user, lp, a, b);
    }

    function get_virtual_price() external view returns (uint256) {
        return ledger.get_virtual_price();
    }

    function removeLiquidity(uint256 lpAmount, IExitObserver12 observer) external {
        uint256 assets = ledger.stageExit(msg.sender, lpAmount);
        observer.onExitQueued12(msg.sender, assets);
        ledger.commitExit(msg.sender, lpAmount, assets);
    }
}

contract RORCurveLedger12 {
    mapping(address => uint256) public lpBalance;
    mapping(address => uint256) public queuedBurn;
    uint256 public totalSupply;
    uint256 public balanceA;
    uint256 public balanceB;
    uint256 public queuedAssets;

    function seed(address user, uint256 lp, uint256 a, uint256 b) external {
        lpBalance[user] = lp;
        totalSupply = lp;
        balanceA = a;
        balanceB = b;
    }

    function get_virtual_price() external view returns (uint256) {
        uint256 visibleAssets = balanceA + balanceB - queuedAssets;
        return visibleAssets * 1e18 / totalSupply;
    }

    function stageExit(address owner, uint256 lpAmount) external returns (uint256 assets) {
        uint256 assets = lpAmount * (balanceA + balanceB) / totalSupply;
        queuedBurn[owner] += lpAmount;
        queuedAssets += assets;
        return assets;
    }

    function commitExit(address owner, uint256 lpAmount, uint256 assets) external {
        queuedBurn[owner] -= lpAmount;
        queuedAssets -= assets;
        lpBalance[owner] -= lpAmount;
        totalSupply -= lpAmount;
        balanceA -= assets / 2;
        balanceB -= assets - assets / 2;
    }
}

contract RORCurveBorrowMarket12 {
    RORCurvePool12 public immutable pool;
    mapping(address => uint256) public minted;

    constructor(RORCurvePool12 pool_) {
        pool = pool_;
    }

    function mint(uint256 lpCollateral) external {
        minted[msg.sender] += lpCollateral * pool.get_virtual_price() / 2e18;
    }
}
