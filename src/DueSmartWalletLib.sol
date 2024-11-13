// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

enum CredentialType {
    EthereumAddress,
    WebAuthn,
    WebAuthnUV
}

struct Credential {
    bytes payload;
    CredentialType credentialType;
}

struct AddSignerCredentialRequest {
    uint256 signerIndex;
    Credential credential;
    uint256 nonce;
}

struct RemoveSignerCredentialRequest {
    uint256 signerIndex;
    uint256 credentialIndex;
    Credential credential;
    uint256 nonce;
}

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
    bytes32 private constant _ADD_SIGNER_CREDENTIAL_REQUEST_TYPEHASH = keccak256(
        "AddSignerCredentialRequest(uint256 signerIndex,Credential credential,uint256 nonce)Credential(bytes payload,uint8 credentialType)"
    );

    bytes32 private constant _REMOVE_SIGNER_CREDENTIAL_REQUEST_TYPEHASH = keccak256(
        "RemoveSignerCredentialRequest(uint256 signerIndex,uint256 credentialIndex,Credential credential,uint256 nonce)Credential(bytes payload,uint8 credentialType)"
    );

    bytes32 private constant _CREDENTIAL_TYPEHASH = keccak256("Credential(bytes credential,uint8 credentialType)");

    bytes32 private constant _OE_MESSAGE_TYPEHASH = keccak256(
        "OutsideExecution(address caller,uint256 nonce,uint256 executeBefore,uint256 executeAfter,uint256 chainId,Call[] calls)Call(address target,uint256 value,bytes data)"
    );
    bytes32 private constant _CALL_MESSAGE_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");

    function hashAddSignerCredentialRequest(AddSignerCredentialRequest memory request)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                _ADD_SIGNER_CREDENTIAL_REQUEST_TYPEHASH,
                request.signerIndex,
                hashCredential(request.credential),
                request.nonce
            )
        );
    }

    function hashRemoveSignerCredentialRequest(RemoveSignerCredentialRequest memory request)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                _REMOVE_SIGNER_CREDENTIAL_REQUEST_TYPEHASH,
                request.signerIndex,
                request.credentialIndex,
                hashCredential(request.credential),
                request.nonce
            )
        );
    }

    function hashCredential(Credential memory credential) internal pure returns (bytes32) {
        return keccak256(abi.encode(_CREDENTIAL_TYPEHASH, keccak256(credential.payload), credential.credentialType));
    }

    function hashCall(Call memory call) internal pure returns (bytes32) {
        return keccak256(abi.encode(_CALL_MESSAGE_TYPEHASH, call.target, call.value, call.data));
    }

    function hashOutsideExecution(OutsideExecution memory oe) internal pure returns (bytes32) {
        bytes32[] memory calls = new bytes32[](oe.calls.length);
        for (uint256 i = 0; i < oe.calls.length; i++) {
            calls[i] = hashCall(oe.calls[i]);
        }

        bytes memory hash = abi.encode(
            _OE_MESSAGE_TYPEHASH,
            oe.caller,
            oe.nonce,
            oe.executeBefore,
            oe.executeAfter,
            oe.chainId,
            keccak256(abi.encodePacked(calls))
        );

        return keccak256(hash);
    }
}
