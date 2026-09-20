// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface WithdrawHook67 {
    function onWithdraw(address account, uint256 amount) external;
}

contract WithdrawWithReadLockSafe67 {
    bool private updating;
    uint256 public totalAssets = 500 ether;
    uint256 public totalSupply = 500 ether;
    WithdrawHook67 public hook;

    constructor(WithdrawHook67 hook_) {
        hook = hook_;
    }

    function withdraw(uint256 shares) external {
        updating = true;
        uint256 assets = (shares * totalAssets) / totalSupply;
        hook.onWithdraw(msg.sender, assets);
        totalSupply -= shares;
        totalAssets -= assets;
        updating = false;
    }

    function pricePerShare() external view returns (uint256) {
        require(!updating, "updating");
        return (totalAssets * 1e18) / totalSupply;
    }
}
