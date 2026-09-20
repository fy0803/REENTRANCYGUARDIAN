pragma solidity ^0.8.0;

contract ConstraintProbe {
    function possible(uint256 x) external pure returns (uint256) {
        uint256 y = x + 1;
        require(y > x, "possible");
        return y;
    }

    function impossible(uint256 x) external pure returns (uint256) {
        uint256 y = x + 1;
        require(y < x, "impossible");
        return y;
    }
}
