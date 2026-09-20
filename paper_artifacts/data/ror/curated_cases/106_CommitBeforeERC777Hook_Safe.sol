// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface ERC777Like106 {
    function send(address to, uint256 amount, bytes calldata data) external;
}

contract CommitBeforeERC777HookSafe106 {
    uint256 public accountingTotal;
    ERC777Like106 public token;

    constructor(ERC777Like106 token_) {
        token = token_;
    }

    function payout(address to, uint256 amount) external {
        accountingTotal -= amount;
        token.send(to, amount, "");
    }

    function totalAccounting() external view returns (uint256) {
        return accountingTotal;
    }
}
