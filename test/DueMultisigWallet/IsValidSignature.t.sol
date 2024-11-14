// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../src/DueMultisigWallet.sol";
import "../../src/DueSmartWalletLib.sol";
import "./DueSmartWalletTestBase.sol";
import "webauthn-sol/../test/Utils.sol";

contract TestIsValidSignature is DueSmartWalletTestBase {
    function addNewPKSigner(uint256 pk, uint256 threshold) internal {
        Credential[] memory credentials = new Credential[](1);
        credentials[0] = Credential(abi.encode(vm.addr(pk)), CredentialType.EthereumAddress);

        Call[] memory calls = new Call[](1);
        calls[0] = Call(
            address(account), 0, abi.encodeWithSelector(DueMultisigWallet.addSigner.selector, credentials, threshold)
        );

        uint256 nonce = account.nextNonce(account.REPLAYABLE_NONCE_KEY());
        OutsideExecution memory oe = OutsideExecution(address(0x0), nonce, 0x0, 0x0, 0x0, calls);

        bytes32 toSign = account.replaySafeHash(DueSmartWalletLib.hashOutsideExecution(oe));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        DueMultisigWallet.SignatureWrapper[] memory sigs = new DueMultisigWallet.SignatureWrapper[](1);
        sigs[0] = DueMultisigWallet.SignatureWrapper(0, 0, signature);
        account.executeFromOutside(oe, sigs);

        assertEq(account.threshold(), threshold);
    }

    function testValidateSignature1SignerEOA() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(account.hashStruct(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        DueMultisigWallet.SignatureWrapper[] memory sigs = new DueMultisigWallet.SignatureWrapper[](1);
        sigs[0] = DueMultisigWallet.SignatureWrapper(0, 0, signature);

        bytes4 ret = account.isValidSignature(hash, abi.encode(sigs));
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignature2SignersEOA() public {
        uint256 signer2PrivateKey = 0xa11cf;
        addNewPKSigner(signer2PrivateKey, 2);

        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(account.hashStruct(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(signer2PrivateKey, toSign);
        bytes memory signature2 = abi.encodePacked(r, s, v);

        DueMultisigWallet.SignatureWrapper[] memory sigs = new DueMultisigWallet.SignatureWrapper[](2);
        sigs[0] = DueMultisigWallet.SignatureWrapper(0, 0, signature);
        sigs[1] = DueMultisigWallet.SignatureWrapper(1, 0, signature2);

        bytes4 ret = account.isValidSignature(hash, abi.encode(sigs));
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWith1SignerPasskey() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(account.hashStruct(hash));
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        DueMultisigWallet.SignatureWrapper[] memory sigs = new DueMultisigWallet.SignatureWrapper[](1);
        sigs[0] = DueMultisigWallet.SignatureWrapper({
            signerIndex: 0,
            credentialIndex: 1,
            signatureData: abi.encode(
                WebAuthn.WebAuthnAuth({
                    authenticatorData: webAuthn.authenticatorData,
                    clientDataJSON: webAuthn.clientDataJSON,
                    typeIndex: 1,
                    challengeIndex: 23,
                    r: uint256(r),
                    s: uint256(s)
                })
            )
        });

        bytes4 ret = account.isValidSignature(hash, abi.encode(sigs));
        assertEq(ret, bytes4(0x1626ba7e));
    }
}
