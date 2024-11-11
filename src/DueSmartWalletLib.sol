// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

struct OutsideExecution {
    address caller;
    uint256 nonce;
    uint256 executeBefore;
    uint256 executeAfter;
    uint256 chainId;
    Call[] calls;
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}

library DueSmartWalletLib {
    function pack(OutsideExecution memory oe) internal pure returns (bytes memory) {
        return abi.encode(oe.caller, oe.nonce, oe.executeBefore, oe.executeAfter, oe.chainId, oe.calls);
    }

    function hash(OutsideExecution memory oe) internal pure returns (bytes32) {
        return keccak256(pack(oe));
    }
}
