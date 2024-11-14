// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "./MultisigTestBase.t.sol";

contract MultisigAddSignerCredentialTest is MockMultisigTestBase {
    function testAddPKCredentialOK() public {
        address signer2Address1 = address(0x001);
        mock.addSignerCredential(0, Credential(abi.encode(signer2Address1), CredentialType.EthereumAddress));
        assertEq(abi.encode(signer2Address1), mock.signerCredentialAtIndex(0, 2).payload);
    }

    function testRevertIfCredentialAlreadyUsed() public {
        vm.expectRevert(abi.encodeWithSelector(Multisig.CredentialAlreadyInUse.selector, abi.encode(signer1Address)));
        mock.addSignerCredential(0, Credential(signer1AddressBytes, CredentialType.EthereumAddress));
    }
}
