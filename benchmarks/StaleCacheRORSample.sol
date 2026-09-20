pragma solidity ^0.8.0;

interface IHook {
    function onDeposit() external;
}

contract StaleCachePool {
    uint256 public cachedTotalAssets;
    uint256 public totalAssets;

    constructor() {
        cachedTotalAssets = 100 ether;
        totalAssets = 100 ether;
    }

    function totalAssetsCached() external view returns (uint256) {
        return cachedTotalAssets;
    }

    function deposit(address hook, uint256 amount) external {
        totalAssets += amount;
        IHook(hook).onDeposit();
        cachedTotalAssets = totalAssets;
    }
}
