// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "./MultisigTestBase.t.sol";

contract MultisigRemoveLastSignerTest is MockMultisigTestBase {
    function testRemoveLastSignerOk() public {
        assertEq(1, mock.signersCount());
        mock.removeLastSigner(0);
        assertEq(0, mock.signersCount());
    }

    function testRevertIfNotLastSigner() public {
        address signer2Address = address(0x001);
        bytes[] memory signer2Credentials = new bytes[](1);
        signer2Credentials[0] = abi.encode(signer2Address);
        mock.addSigner(signer2Credentials, 1);

        vm.expectRevert(abi.encodeWithSelector(Multisig.NotLastSigner.selector, mock.signersCount()));
        mock.removeLastSigner(0);
    }
}
