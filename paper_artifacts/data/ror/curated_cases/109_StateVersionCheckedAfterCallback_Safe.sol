// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface VersionHook109 {
    function mayCallback() external;
}

contract StateVersionCheckedAfterCallbackSafe109 {
    uint256 public version;
    uint256 public value;
    VersionHook109 public hook;

    constructor(VersionHook109 hook_) {
        hook = hook_;
    }

    function update(uint256 nextValue) external {
        uint256 nextVersion = version + 1;
        value = nextValue;
        version = nextVersion;
        hook.mayCallback();
        require(version == nextVersion, "version changed");
    }

    function read() external view returns (uint256, uint256) {
        return (value, version);
    }
}
