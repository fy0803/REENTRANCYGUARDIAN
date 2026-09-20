// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Controller77 {
    function withdraw(uint256 assets) external;
}

contract ControllerWithdrawNoShareMutationSafe77 {
    uint256 public totalSupply = 1_000 ether;
    uint256 public totalAssets = 1_000 ether;
    Controller77 public controller;

    constructor(Controller77 controller_) {
        controller = controller_;
    }

    function withdrawFromController(uint256 assets) external {
        controller.withdraw(assets);
    }

    function pricePerShare() external view returns (uint256) {
        return (totalAssets * 1e18) / totalSupply;
    }
}
