// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface AccumulatorHook104 {
    function afterAccrual() external;
}

contract CallbackReadsFinalizedAccumulatorSafe104 {
    uint256 public accumulator;
    uint256 private workingAccumulator;
    AccumulatorHook104 public hook;

    constructor(AccumulatorHook104 hook_) {
        hook = hook_;
    }

    function accrue(uint256 delta) external {
        workingAccumulator = accumulator + delta;
        accumulator = workingAccumulator;
        hook.afterAccrual();
    }

    function readAccumulator() external view returns (uint256) {
        return accumulator;
    }
}
