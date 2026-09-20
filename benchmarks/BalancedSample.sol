pragma solidity ^0.8.0;

contract BalancedPool {
    uint256 public totalStaked;
    uint256 public totalShares;

    constructor() {
        totalStaked = 100 ether;
        totalShares = 100 ether;
    }

    function getPrice() public view returns (uint256) {
        return totalStaked * 1e18 / totalShares;
    }

    function safeUnstake(uint256 shareAmount) external {
        uint256 ethAmount = shareAmount * getPrice() / 1e18;
        totalStaked -= ethAmount;
        totalShares -= shareAmount;

        (bool ok,) = msg.sender.call{value: ethAmount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}

contract BalancedVault {
    BalancedPool public pool;
    mapping(address => uint256) public shares;

    constructor(BalancedPool _pool) {
        pool = _pool;
    }

    function deposit() external payable {
        uint256 price = pool.getPrice();
        uint256 mintAmount = msg.value * 1e18 / price;
        shares[msg.sender] += mintAmount;
    }
}
