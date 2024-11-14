// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "./MultisigTestBase.t.sol";

contract MultisigRemoveSignerTest is MockMultisigTestBase {
    function testRemoveSignerOk() public {
        address signer2Address = address(0x001);
        Credential[] memory signer2Credentials = new Credential[](1);
        signer2Credentials[0] = Credential(abi.encode(signer2Address), CredentialType.EthereumAddress);

        mock.addSigner(signer2Credentials, 2);
        assertEq(2, mock.signersCount());
        assertEq(2, mock.threshold());

        mock.removeSigner(1, 1);
        assertEq(1, mock.signersCount());
        assertEq(1, mock.threshold());
        assertEq("", mock.signerCredentialAtIndex(1, 0).payload);

        // check that we can add a new signer with the same credentials afetr removing the old one
        mock.addSigner(signer2Credentials, 2);
        assertEq(2, mock.signersCount());
        assertEq(2, mock.threshold());
    }

    function testRevertIfRemovingLastSigner() public {
        vm.expectRevert(abi.encodeWithSelector(Multisig.CannotRemoveLastSigner.selector));
        mock.removeSigner(0, 1);
    }
}
