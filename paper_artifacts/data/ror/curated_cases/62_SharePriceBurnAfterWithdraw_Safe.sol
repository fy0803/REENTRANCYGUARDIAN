// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Controller62 {
    function withdraw(uint256 assets) external;
}

contract SharePriceBurnAfterWithdrawSafe62 {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    Controller62 public controller;

    constructor(Controller62 controller_) {
        controller = controller_;
        totalAssets = 1_000 ether;
        totalSupply = 1_000 ether;
        balanceOf[msg.sender] = 1_000 ether;
    }

    function withdraw(uint256 shares) external {
        require(balanceOf[msg.sender] >= shares, "insufficient shares");
        uint256 assets = (shares * totalAssets) / totalSupply;
        controller.withdraw(assets);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        totalAssets -= assets;
    }

    function pricePerShare() external view returns (uint256) {
        return (totalAssets * 1e18) / totalSupply;
    }
}
