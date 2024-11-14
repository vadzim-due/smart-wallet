// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {Test, console2, stdError} from "forge-std/Test.sol";

import "../../src/DueMultisigWallet.sol";
import {MockDueSmartWallet} from "../mocks/MockDueSmartWallet.sol";

contract DueSmartWalletTestBase is Test {
    DueMultisigWallet public account;
    uint256 signerPrivateKey = 0xa11ce;
    address signer = vm.addr(signerPrivateKey);
    Credential[] owners;
    uint256 passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    bytes passkeyOwner =
        hex"1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d";
    IEntryPoint entryPoint = IEntryPoint(0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789);
    address bundler = address(uint160(uint256(keccak256(abi.encodePacked("bundler")))));

    function setUp() public virtual {
        account = new MockDueSmartWallet();
        owners.push(Credential(abi.encode(signer), CredentialType.EthereumAddress));
        owners.push(Credential(passkeyOwner, CredentialType.WebAuthn));
        account.initialize(owners);
    }
}
