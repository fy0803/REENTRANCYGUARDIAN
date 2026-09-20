// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Asset86 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract WithdrawBurnBeforeExternalCallSafe86 {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    Asset86 public asset;

    constructor(Asset86 asset_) {
        asset = asset_;
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        totalShares -= amount;
        require(asset.transfer(msg.sender, amount), "transfer failed");
    }

    function pricePerShare() external view returns (uint256) {
        return totalShares == 0 ? 1e18 : (address(this).balance * 1e18) / totalShares;
    }
}
