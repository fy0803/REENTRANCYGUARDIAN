// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ReserveCallback71 {
    function onIndexUpdated(uint256 index) external;
}

contract ReserveIndexCommitBeforeCallbackSafe71 {
    uint256 public reserveIndex = 1e27;
    ReserveCallback71 public callback;

    constructor(ReserveCallback71 callback_) {
        callback = callback_;
    }

    function accrue(uint256 delta) external {
        reserveIndex += delta;
        callback.onIndexUpdated(reserveIndex);
    }

    function liquidityIndex() external view returns (uint256) {
        return reserveIndex;
    }
}
