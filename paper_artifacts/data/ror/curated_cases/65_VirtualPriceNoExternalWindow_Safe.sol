// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract VirtualPriceNoExternalWindowSafe65 {
    uint256 public totalLiquidity = 1_000 ether;
    uint256 public totalLpSupply = 1_000 ether;

    function rebalance(uint256 newLiquidity) external {
        totalLiquidity = newLiquidity;
    }

    function virtualPrice() external view returns (uint256) {
        return (totalLiquidity * 1e18) / totalLpSupply;
    }
}
