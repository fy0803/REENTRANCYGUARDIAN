pragma solidity ^0.8.0;

contract OracleFeed {
    uint256 public price = 42 ether;

    function peek() external view returns (uint256) {
        return price;
    }
}

contract StaticConsumer {
    address public oracle;
    uint256 public cachedPrice;

    constructor(address _oracle) {
        oracle = _oracle;
    }

    function refresh() external {
        (bool ok, bytes memory data) = oracle.staticcall(
            abi.encodeWithSignature("peek()")
        );
        require(ok, "staticcall failed");
        cachedPrice = abi.decode(data, (uint256));
    }
}
