// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface CollateralHook72 {
    function onExit(uint256 amount) external;
}

contract CollateralIndexReadGuardSafe72 {
    bool private settling;
    uint256 public collateralIndex = 1e18;
    CollateralHook72 public hook;

    constructor(CollateralHook72 hook_) {
        hook = hook_;
    }

    function exit(uint256 amount) external {
        settling = true;
        hook.onExit(amount);
        collateralIndex += amount / 1e9;
        settling = false;
    }

    function getCollateralIndex() external view returns (uint256) {
        require(!settling, "settling");
        return collateralIndex;
    }
}
