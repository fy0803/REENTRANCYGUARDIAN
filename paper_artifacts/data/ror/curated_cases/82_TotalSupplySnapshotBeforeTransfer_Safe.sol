// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Token82 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TotalSupplySnapshotBeforeTransferSafe82 {
    uint256 public totalSupplySnapshot;
    Token82 public rewardToken;

    constructor(Token82 rewardToken_) {
        rewardToken = rewardToken_;
    }

    function distribute(address to, uint256 amount, uint256 currentSupply) external {
        totalSupplySnapshot = currentSupply;
        require(rewardToken.transfer(to, amount), "transfer failed");
    }

    function observedSupply() external view returns (uint256) {
        return totalSupplySnapshot;
    }
}
