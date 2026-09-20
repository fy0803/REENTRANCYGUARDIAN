// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface SettleHook111 {
    function afterSettleStart() external;
}

contract OracleReadBlockedUntilSettledSafe111 {
    bool public settling;
    uint256 public settledPrice;
    SettleHook111 public hook;

    constructor(SettleHook111 hook_) {
        hook = hook_;
    }

    function settle(uint256 nextPrice) external {
        settling = true;
        settledPrice = nextPrice;
        hook.afterSettleStart();
        settling = false;
    }

    function price() external view returns (uint256) {
        require(!settling, "settling");
        return settledPrice;
    }
}
