// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import "./MultisigTestBase.t.sol";

contract MultisigAddNewSignerTest is MockMultisigTestBase {
    function testAddPKSignerOK() public {
        assertEq(1, mock.threshold());
        assertEq(1, mock.nextSignerIndex());

        address signer2Address1 = address(0x001);
        bytes[] memory signer2Credentials = new bytes[](1);
        signer2Credentials[0] = abi.encode(signer2Address1);

        mock.addSigner(signer2Credentials, 2);
        assertEq(2, mock.threshold());
        assertEq(2, mock.nextSignerIndex());
        assertEq(signer2Credentials[0], mock.signerCredentialAtIndex(1, 0));
    }

    function testAddSignerRevertsIfCredentialAlreadyUsed() public {
        bytes[] memory signer2Credentials = new bytes[](1);
        signer2Credentials[0] = abi.encode(signer1Address);

        vm.expectRevert(abi.encodeWithSelector(Multisig.SignerAlreadyExists.selector, abi.encode(signer1Address)));
        mock.addSigner(signer2Credentials, 2);
    }
}
