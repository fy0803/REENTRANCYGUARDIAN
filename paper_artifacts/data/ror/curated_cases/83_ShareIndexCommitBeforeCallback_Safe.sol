// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Callback83 {
    function notify() external;
}

contract ShareIndexCommitBeforeCallbackSafe83 {
    uint256 public shareIndex = 1e18;
    Callback83 public callback;

    constructor(Callback83 callback_) {
        callback = callback_;
    }

    function accrue(uint256 interest) external {
        shareIndex += interest;
        callback.notify();
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return (shares * shareIndex) / 1e18;
    }
}
