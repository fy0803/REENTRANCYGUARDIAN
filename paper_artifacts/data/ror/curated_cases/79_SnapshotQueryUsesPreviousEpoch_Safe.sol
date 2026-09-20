// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface EpochHook79 {
    function afterEpoch(uint256 epoch) external;
}

contract SnapshotQueryUsesPreviousEpochSafe79 {
    uint256 public currentEpoch;
    mapping(uint256 => uint256) public epochPrice;
    EpochHook79 public hook;

    constructor(EpochHook79 hook_) {
        hook = hook_;
        epochPrice[0] = 1e18;
    }

    function closeEpoch(uint256 price) external {
        currentEpoch += 1;
        hook.afterEpoch(currentEpoch);
        epochPrice[currentEpoch] = price;
    }

    function latestFinalizedPrice() external view returns (uint256) {
        return epochPrice[currentEpoch - 1];
    }
}
