// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface ILpTokenLike {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function mint(address account, uint256 amount) external;
    function burn(address account, uint256 amount) external;
}

/// @notice Reduced Conic EthPool sample for read-only reentrancy detection.
/// @dev The external token/LP calls happen before the cached total is refreshed.
///      A callback can read cachedTotalUnderlying() and observe stale accounting.
contract ConicEthPool {
    uint256 internal constant ONE = 1e18;
    uint256 internal constant _TOTAL_UNDERLYING_CACHE_EXPIRY = 3 days;

    IERC20Like public immutable underlying;
    ILpTokenLike public immutable lpToken;

    uint256 internal _cacheUpdatedTimestamp;
    uint256 internal _cachedTotalUnderlying;
    uint256 public totalUnderlying;

    event Deposit(address indexed sender, address indexed account, uint256 underlyingAmount, uint256 lpReceived);
    event Withdraw(address indexed account, uint256 underlyingWithdrawn);

    constructor(IERC20Like underlying_, ILpTokenLike lpToken_) {
        underlying = underlying_;
        lpToken = lpToken_;
        totalUnderlying = 100 ether;
        _cachedTotalUnderlying = totalUnderlying;
        _cacheUpdatedTimestamp = block.timestamp;
    }

    function depositFor(
        address account,
        uint256 underlyingAmount,
        uint256 minLpReceived,
        bool stake
    ) public returns (uint256) {
        require(underlyingAmount > 0, "deposit amount cannot be zero");

        uint256 totalBefore = totalUnderlying;
        uint256 exchangeRateBefore = _exchangeRate(totalBefore);

        underlying.transferFrom(msg.sender, address(this), underlyingAmount);

        totalUnderlying = totalBefore + underlyingAmount;
        uint256 lpReceived = underlyingAmount * ONE / exchangeRateBefore;
        require(lpReceived >= minLpReceived, "too much slippage");

        if (stake) {
            lpToken.mint(address(this), lpReceived);
        } else {
            lpToken.mint(account, lpReceived);
        }

        _cachedTotalUnderlying = totalUnderlying;
        _cacheUpdatedTimestamp = block.timestamp;

        emit Deposit(msg.sender, account, underlyingAmount, lpReceived);
        return lpReceived;
    }

    function deposit(uint256 underlyingAmount, uint256 minLpReceived) external returns (uint256) {
        return depositFor(msg.sender, underlyingAmount, minLpReceived, true);
    }

    function withdraw(uint256 conicLpAmount, uint256 minUnderlyingReceived) public returns (uint256) {
        require(lpToken.balanceOf(msg.sender) >= conicLpAmount, "insufficient balance");

        uint256 totalBefore = totalUnderlying;
        uint256 underlyingWithdrawn = conicLpAmount * _exchangeRate(totalBefore) / ONE;
        require(underlyingWithdrawn >= minUnderlyingReceived, "too much slippage");

        lpToken.burn(msg.sender, conicLpAmount);
        underlying.transfer(msg.sender, underlyingWithdrawn);

        totalUnderlying = totalBefore - underlyingWithdrawn;
        _cachedTotalUnderlying = totalUnderlying;
        _cacheUpdatedTimestamp = block.timestamp;

        emit Withdraw(msg.sender, underlyingWithdrawn);
        return underlyingWithdrawn;
    }

    function cachedTotalUnderlying() external view returns (uint256) {
        if (block.timestamp > _cacheUpdatedTimestamp + _TOTAL_UNDERLYING_CACHE_EXPIRY) {
            return totalUnderlying;
        }
        return _cachedTotalUnderlying;
    }

    function exchangeRate() external view returns (uint256) {
        return _exchangeRate(_cachedTotalUnderlying);
    }

    function _exchangeRate(uint256 totalUnderlying_) internal view returns (uint256) {
        uint256 supply = lpToken.totalSupply();
        if (supply == 0 || totalUnderlying_ == 0) {
            return ONE;
        }
        return totalUnderlying_ * ONE / supply;
    }
}
