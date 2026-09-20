// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface Escrow115 {
    function release(uint256 amount) external;
}

contract TotalAssetsReadUsesEscrowBalanceSafe115 {
    uint256 public escrowedAssets;
    Escrow115 public escrow;

    constructor(Escrow115 escrow_) {
        escrow = escrow_;
    }

    function release(uint256 amount) external {
        require(escrowedAssets >= amount, "insufficient");
        escrowedAssets -= amount;
        escrow.release(amount);
    }

    function totalAssets() external view returns (uint256) {
        return escrowedAssets;
    }
}
