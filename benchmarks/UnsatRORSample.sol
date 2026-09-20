pragma solidity ^0.8.0;

contract UnsatPool {
    uint256 public totalStaked;
    uint256 public totalShares;

    constructor() {
        totalStaked = 100 ether;
        totalShares = 100 ether;
    }

    function getPrice() public view returns (uint256) {
        return totalStaked * 1e18 / totalShares;
    }

    function unstake(uint256 shareAmount) external {
        uint256 ethAmount = shareAmount * getPrice() / 1e18;
        totalStaked -= ethAmount;

        (bool ok,) = msg.sender.call{value: ethAmount}("");
        require(ok, "transfer failed");

        totalShares -= shareAmount;
    }

    receive() external payable {}
}

contract UnsatVault {
    UnsatPool public pool;
    mapping(address => uint256) public shares;

    constructor(UnsatPool _pool) {
        pool = _pool;
    }

    function depositImpossible() external payable {
        uint256 price = pool.getPrice();
        require(price > 0 && price == 0, "impossible price");
        uint256 mintAmount = msg.value * 1e18 / price;
        shares[msg.sender] += mintAmount;
    }
}
