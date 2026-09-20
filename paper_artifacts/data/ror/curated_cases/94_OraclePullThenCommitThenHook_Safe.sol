// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface SourceOracle94 {
    function read() external view returns (uint256);
}

interface Hook94 {
    function afterRead() external;
}

contract OraclePullThenCommitThenHookSafe94 {
    uint256 public price;
    SourceOracle94 public source;
    Hook94 public hook;

    constructor(SourceOracle94 source_, Hook94 hook_) {
        source = source_;
        hook = hook_;
    }

    function update() external {
        uint256 nextPrice = source.read();
        price = nextPrice;
        hook.afterRead();
    }

    function latestPrice() external view returns (uint256) {
        return price;
    }
}
