// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface DebtHook74 {
    function afterMint(address account, uint256 shares) external;
}

contract DebtShareIndexConsistentUpdateSafe74 {
    uint256 public totalDebt = 1_000 ether;
    uint256 public totalDebtShares = 1_000 ether;
    DebtHook74 public hook;

    constructor(DebtHook74 hook_) {
        hook = hook_;
    }

    function mintDebtShares(uint256 shares) external {
        uint256 debt = (shares * totalDebt) / totalDebtShares;
        totalDebtShares += shares;
        totalDebt += debt;
        hook.afterMint(msg.sender, shares);
    }

    function debtIndex() external view returns (uint256) {
        return (totalDebt * 1e18) / totalDebtShares;
    }
}
