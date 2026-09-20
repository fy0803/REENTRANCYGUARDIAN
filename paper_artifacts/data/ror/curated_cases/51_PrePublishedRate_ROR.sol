// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISettlement51 {
    function settle51(address account, uint256 shares, uint256 assets) external;
}

contract PrePublishedRate51 {
    struct Account {
        uint256 shares;
        uint256 pendingAssets;
        uint256 lastRound;
    }

    struct RateConfig {
        uint256 minLiquidity;
        uint256 maxExitBps;
        bool paused;
    }

    mapping(address => Account) public accounts;
    uint256 public totalSupply = 1_000 ether;
    uint256 public backingAssets = 1_000 ether;
    uint256 public pendingExitAssets;
    uint256 public publishedRate = 1e18;
    uint256 public accountingRound;
    RateConfig public config = RateConfig({minLiquidity: 10 ether, maxExitBps: 5_000, paused: false});

    event ExitQueued(address indexed account, uint256 shares, uint256 assets, uint256 rate);

    modifier whenNotPaused() {
        require(!config.paused, "PAUSED");
        _;
    }

    function seed(address user, uint256 shares, uint256 assets) external {
        accounts[user].shares = shares;
        totalSupply = shares == 0 ? totalSupply : shares;
        backingAssets = assets == 0 ? backingAssets : assets;
        publishedRate = backingAssets * 1e18 / totalSupply;
    }

    function getRate() external view returns (uint256) {
        return publishedRate;
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return shares * publishedRate / 1e18;
    }

    function availableAssets() external view returns (uint256) {
        return backingAssets - pendingExitAssets;
    }

    function unwrap(uint256 shares, address settlement) external whenNotPaused {
        Account storage account = accounts[msg.sender];
        require(shares != 0 && shares <= account.shares, "BAD_SHARES");
        require(shares * 10_000 <= totalSupply * config.maxExitBps, "EXIT_TOO_LARGE");

        uint256 assets = previewRedeem(shares);
        require(backingAssets >= pendingExitAssets + assets + config.minLiquidity, "LIQUIDITY");

        account.shares -= shares;
        account.pendingAssets += assets;
        account.lastRound = ++accountingRound;
        totalSupply -= shares;
        pendingExitAssets += assets;
        publishedRate = backingAssets * 1e18 / totalSupply;

        emit ExitQueued(msg.sender, shares, assets, publishedRate);
        ISettlement51(settlement).settle51(msg.sender, shares, assets);
    }
}

