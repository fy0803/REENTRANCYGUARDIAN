// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface InvariantHook116 {
    function afterRestore() external;
}

contract CallbackAfterInvariantRestoredSafe116 {
    uint256 public reserve;
    uint256 public liabilities;
    InvariantHook116 public hook;

    constructor(InvariantHook116 hook_) {
        hook = hook_;
    }

    function rebalance(uint256 nextReserve, uint256 nextLiabilities) external {
        require(nextReserve >= nextLiabilities, "undercollateralized");
        reserve = nextReserve;
        liabilities = nextLiabilities;
        hook.afterRestore();
    }

    function solvencyRatio() external view returns (uint256) {
        return liabilities == 0 ? type(uint256).max : (reserve * 1e18) / liabilities;
    }
}
