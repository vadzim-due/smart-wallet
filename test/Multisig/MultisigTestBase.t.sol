// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console2, stdError} from "forge-std/Test.sol";

import "../mocks/MockMultisig.sol";

contract MockMultisigTestBase is Test {
    MockMultisig mock = new MockMultisig();
    address signer1Address = address(0xb0b);
    bytes signer1AddressBytes = abi.encode(signer1Address);
    bytes signer1PublicKey = abi.encode(
        0x65a2fa44daad46eab0278703edb6c4dcf5e30b8a9aec09fdc71a56f52aa392e4,
        0x4a7a9e4604aa36898209997288e902ac544a555e4b5e0a9efef2b59233f3f437
    );
    Credential[] credentials;

    function setUp() public virtual {
        credentials.push(Credential(signer1AddressBytes, CredentialType.EthereumAddress));
        credentials.push(Credential(signer1PublicKey, CredentialType.WebAuthn));
        mock.init(credentials);
    }
}
