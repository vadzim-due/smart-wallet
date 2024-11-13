// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Credential} from "./DueSmartWalletLib.sol";

struct MultisigStorage {
    uint256 signaturesThreshold;
    uint256 nextSignerIndex;
    mapping(uint256 signerIndex => uint256 nextCredentialIndex) nextCredentialIndex;
    uint256 removedSignersCount;
    mapping(uint256 signerIndex => uint256 removedCredentialsCount) removedCredentialsCount;
    // index to check if credential is already by a signer
    mapping(bytes credential => bool isSigner_) isSigner;
    mapping(uint256 signerIndex => mapping(uint256 credentialIndex => Credential credential)) signerCredentialAtIndex;
    mapping(uint192 key => uint64 nonce) nonces;
}

contract Multisig {
    event SignerAdded(uint256 indexed index);
    event SignerRemoved(uint256 indexed index);
    event CredentialAdded(uint256 indexed index, uint256 credentialIndex, Credential credential);
    event CredentialRemoved(uint256 indexed index, uint256 credentialIndex, Credential credential);
    event ThresholdChanged(uint256 oldThreshold, uint256 newThreshold);

    error CredentialAlreadyInUse(bytes credential);
    error SignerNotFound(uint256 index);
    error SignerCredentialNotFound(uint256 index, uint256 credentialIndex);
    error SignerCredentialMismatch(uint256 index, uint256 credentialIndex, bytes expected, bytes actual);
    error CannotRemoveSignerLastCredential();
    error CannotRemoveLastSigner();
    error NotLastSigner(uint256 remaining);
    error UnexpectedNonceValue(uint192 key, uint64 expectedValue, uint64 gotValue);
    error InvalidCredentialLength(bytes credential);
    error InvalidEthereumAddress(bytes credential);
    error InvalidThreshold(uint256 threshold, uint256 signerCount);

    function nextNonce(uint192 key) public view virtual returns (uint256) {
        return _getMultisigStorage().nonces[key] + 1 | (uint256(key) << 64);
    }

    function getNonce(uint192 key) public view virtual returns (uint256) {
        return _getMultisigStorage().nonces[key] | (uint256(key) << 64);
    }

    function threshold() public view virtual returns (uint256) {
        return _getMultisigStorage().signaturesThreshold;
    }

    function signerCredentialAtIndex(uint256 index, uint256 credentialIndex)
        public
        view
        virtual
        returns (Credential memory)
    {
        return _getMultisigStorage().signerCredentialAtIndex[index][credentialIndex];
    }

    function nextSignerIndex() public view virtual returns (uint256) {
        return _getMultisigStorage().nextSignerIndex;
    }

    function signersCount() public view virtual returns (uint256) {
        MultisigStorage storage $ = _getMultisigStorage();
        return $.nextSignerIndex - $.removedSignersCount;
    }

    function signerCredentialsCount(uint256 index) public view virtual returns (uint256) {
        MultisigStorage storage $ = _getMultisigStorage();
        return $.nextCredentialIndex[index] - $.removedCredentialsCount[index];
    }

    function _addSigner(Credential[] memory credentials, uint256 newThreshold) internal virtual {
        MultisigStorage storage $ = _getMultisigStorage();

        uint256 index = $.nextSignerIndex++;

        for (uint256 i = 0; i < credentials.length; i++) {
            _addSignerCredential(index, credentials[i]);
        }

        emit SignerAdded(index);
        _updateThreshold(newThreshold);
    }

    function _addSignerCredential(uint256 index, Credential memory credential) internal virtual {
        MultisigStorage storage $ = _getMultisigStorage();

        _validateCredential(credential);
        if ($.isSigner[credential.payload]) {
            revert CredentialAlreadyInUse(credential.payload);
        }
        $.isSigner[credential.payload] = true;

        uint256 credentialIndex = $.nextCredentialIndex[index]++;
        $.signerCredentialAtIndex[index][credentialIndex] = credential;

        emit CredentialAdded(index, credentialIndex, credential);
    }

    function _validateCredential(Credential memory credential) internal pure {
        uint256 length = credential.payload.length;
        if (length != 32 && length != 64) {
            revert InvalidCredentialLength(credential.payload);
        }

        if (length == 32) {
            bytes32 addr = bytes32(credential.payload);
            if (uint256(addr) > type(uint160).max) {
                revert InvalidEthereumAddress(credential.payload);
            }
        }
    }

    function _updateThreshold(uint256 newThreshold) internal virtual {
        MultisigStorage storage $ = _getMultisigStorage();
        uint256 oldThreshold = $.signaturesThreshold;

        if (newThreshold == oldThreshold) return;

        uint256 count = signersCount();
        if (newThreshold <= 0 || newThreshold > count) {
            revert InvalidThreshold(newThreshold, count);
        }

        $.signaturesThreshold = newThreshold;
        emit ThresholdChanged(oldThreshold, newThreshold);
    }

    function _addNonce(uint256 nonce) internal virtual {
        MultisigStorage storage $ = _getMultisigStorage();

        uint192 key = uint192(nonce >> 64);
        uint64 value = uint64(nonce);

        if ($.nonces[key] + 1 != value) {
            revert UnexpectedNonceValue(key, $.nonces[key] + 1, value);
        }
        $.nonces[key] = value;
    }

    function _removeSigner(uint256 index, uint256 newThreshold) internal virtual {
        if (signersCount() == 1) {
            revert CannotRemoveLastSigner();
        }
        _removeSignerAtIndex(index);
        _updateThreshold(newThreshold);
    }

    /// @notice Removes the last remaining signer
    /// @param index Index of signer to remove
    function _removeLastSigner(uint256 index) internal virtual {
        uint256 remaining = signersCount();
        if (remaining > 1) {
            revert NotLastSigner(remaining);
        }
        _removeSignerAtIndex(index);
    }

    function _removeSignerAtIndex(uint256 index) internal virtual {
        MultisigStorage storage $ = _getMultisigStorage();

        bool found = false;
        for (uint256 i = 0; i < signerCredentialsCount(index); i++) {
            Credential memory credential = $.signerCredentialAtIndex[index][i];
            if (credential.payload.length == 0) {
                continue;
            }

            found = true;
            _removeSignerCredentialAtIndex(index, i, credential);
        }

        if (!found) {
            revert SignerNotFound(index);
        }

        $.removedSignersCount++;
        emit SignerRemoved(index);
    }

    function _removeSignerCredential(uint256 index, uint256 credentialIndex, Credential memory signerCredential)
        internal
        virtual
    {
        if (signerCredentialsCount(index) == 1) {
            revert CannotRemoveSignerLastCredential();
        }
        _removeSignerCredentialAtIndex(index, credentialIndex, signerCredential);
    }

    function _removeSignerCredentialAtIndex(
        uint256 index,
        uint256 credentialIndex,
        Credential memory expectedCredential
    ) private {
        MultisigStorage storage $ = _getMultisigStorage();

        Credential memory credential = $.signerCredentialAtIndex[index][credentialIndex];
        if (credential.payload.length == 0) {
            revert SignerCredentialNotFound(index, credentialIndex);
        }

        if (keccak256(credential.payload) != keccak256(expectedCredential.payload)) {
            revert SignerCredentialMismatch(index, credentialIndex, expectedCredential.payload, credential.payload);
        }

        delete $.isSigner[credential.payload];
        delete $.signerCredentialAtIndex[index][credentialIndex];
        $.removedCredentialsCount[index]++;

        emit CredentialRemoved(index, credentialIndex, credential);
    }

    /// @dev ERC-7201 namespace storage location
    bytes32 private constant MULTISIG_STORAGE_LOCATION =
        keccak256(abi.encode(uint256(keccak256("due.storage.Multisig")) - 1)) & ~bytes32(uint256(0xff));

    function _getMultisigStorage() internal pure returns (MultisigStorage storage $) {
        bytes32 location = MULTISIG_STORAGE_LOCATION;
        assembly {
            $.slot := location
        }
    }
}
