// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console2} from "forge-std/Test.sol";

contract MockTarget {
    error TargetError(bytes data);

    bytes32 public datahash;

    bytes public data;

    function setData(bytes memory data_) public payable returns (bytes memory) {
        console2.log("setData start");
        console2.log("msg.sender", msg.sender);
        console2.log("address(this)", address(this));

        data = data_;
        datahash = keccak256(data_);
        return data_;
    }

    function revertWithTargetError(bytes memory data_) public payable {
        revert TargetError(data_);
    }

    function changeOwnerSlotValue(bool change) public payable {
        /// @solidity memory-safe-assembly
        assembly {
            if change { sstore(not(0x8b78c6d8), 0x112233) }
        }
    }
}
