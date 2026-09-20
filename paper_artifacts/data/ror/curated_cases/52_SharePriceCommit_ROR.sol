// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IWithdrawalRouter52 {
    function dispatch52(address account, uint256 shares, uint256 assets) external;
}

contract SharePriceCommit52 {
    struct Withdrawal {
        uint256 shares;
        uint256 assets;
        uint256 nonce;
    }

    mapping(address => uint256) public shareBalance;
    mapping(address => Withdrawal) public queued;
    uint256 public totalShares = 1_000 ether;
    uint256 public totalAssets = 1_000 ether;
    uint256 public lockedAssets;
    uint256 public pricePerShareCache = 1e18;
    uint256 public nonce;
    address public feeRecipient;

    event WithdrawalCommitted(address indexed account, uint256 shares, uint256 assets, uint256 price);

    constructor() {
        feeRecipient = msg.sender;
    }

    function seed(address user, uint256 shares, uint256 assets) external {
        shareBalance[user] = shares;
        totalShares = shares;
        totalAssets = assets;
        pricePerShareCache = assets * 1e18 / shares;
    }

    function pricePerShare() external view returns (uint256) {
        return pricePerShareCache;
    }

    function maxWithdraw(address user) external view returns (uint256) {
        return shareBalance[user] * pricePerShareCache / 1e18;
    }

    function _quoteAssets(uint256 shares) internal view returns (uint256) {
        return shares * pricePerShareCache / 1e18;
    }

    function queueWithdraw(uint256 shares, address router) external {
        require(shares > 0 && shares <= shareBalance[msg.sender], "BAD_SHARES");
        uint256 assets = _quoteAssets(shares);
        require(totalAssets >= lockedAssets + assets, "LOCKED");

        shareBalance[msg.sender] -= shares;
        totalShares -= shares;
        lockedAssets += assets;
        queued[msg.sender] = Withdrawal({shares: shares, assets: assets, nonce: ++nonce});
        pricePerShareCache = totalAssets * 1e18 / totalShares;

        emit WithdrawalCommitted(msg.sender, shares, assets, pricePerShareCache);
        IWithdrawalRouter52(router).dispatch52(msg.sender, shares, assets);
    }
}

