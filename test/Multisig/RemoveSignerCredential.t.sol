// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "./MultisigTestBase.t.sol";

contract MultisigRemoveSignerCredentialTest is MockMultisigTestBase {
    function testRemoveSignerCredentialOk() public {
        assertEq(2, mock.signerCredentialsCount(0));
        mock.removeSignerCredential(0, 0, Credential(signer1AddressBytes, CredentialType.EthereumAddress));
        assertEq(1, mock.signerCredentialsCount(0));
        assertEq("", mock.signerCredentialAtIndex(0, 0).payload);

        // check that we can add a new signer with the same credentials afetr removing the old one
        mock.addSignerCredential(0, Credential(signer1AddressBytes, CredentialType.EthereumAddress));
    }

    function testRevertIfRemovingLastSigner() public {
        mock.removeSignerCredential(0, 1, Credential(signer1PublicKey, CredentialType.WebAuthn));
        vm.expectRevert(abi.encodeWithSelector(Multisig.CannotRemoveSignerLastCredential.selector));
        mock.removeSignerCredential(0, 0, Credential(signer1AddressBytes, CredentialType.EthereumAddress));
    }
}
