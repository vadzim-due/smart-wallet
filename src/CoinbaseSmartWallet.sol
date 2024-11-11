// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {ERC1271} from "./DueERC1271.sol";
import {Call, DueSmartWalletLib, OutsideExecution} from "./DueSmartWalletLib.sol";
import {Multisig} from "./Multisig.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

contract DueMultisigWallet is ERC1271, IAccount, Multisig, UUPSUpgradeable, Receiver {
    struct SignatureWrapper {
        uint256 signerIndex;
        uint256 credentialIndex;
        bytes signatureData;
    }

    /// @notice Reserved nonce key for cross-chain replayable transactions
    uint192 public constant REPLAYABLE_NONCE_KEY = 8453;

    // Authorization errors
    error Unauthorized();
    error Initialized();

    // Cross-chain errors
    error SelectorNotAllowed(bytes4 selector);
    error InvalidNonceKey(uint256 key);

    // Signature errors
    error NotEnoughSignatures();
    error InvalidSignerIndex(uint256 signerIndex);
    error UnexpectedSignerIndex(uint256 expected, uint256 actual);
    error MultipleSignaturesForSameSigner(uint256 signerIndex);
    error InvalidSignature(bytes32 hash, SignatureWrapper[] signatures);
    error FailedToCheckContractSignature(address contractAddress);

    // Execution errors
    error CallerMismatch(address caller, address expectedCaller);
    error InvalidExecuteBefore(uint256 executeBefore, uint256 now);
    error InvalidExecuteAfter(uint256 executeAfter, uint256 now);
    error InvalidChainId(uint256 chainId, uint256 expectedChainId);

    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) revert Unauthorized();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert Unauthorized();
        _;
    }

    /// @notice Handles prefund payment to EntryPoint
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        assembly ("memory-safe") {
            if missingAccountFunds {
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    constructor() {
        bytes[] memory credentials = new bytes[](1);
        credentials[0] = abi.encode(address(0));
        _addSigner(credentials, 1);
    }

    function initialize(bytes[] memory credentials) external payable virtual {
        if (nextSignerIndex() != 0) revert Initialized();
        _addSigner(credentials, 1);
    }

    function addSigner(bytes[] calldata credentials, uint256 newThreshold) public onlySelf {
        _addSigner(credentials, newThreshold);
    }

    function removeSigner(uint256 index, uint256 newThreshold) public onlySelf {
        _removeSigner(index, newThreshold);
    }

    function removeLastSigner(uint256 index) public onlySelf {
        _removeLastSigner(index);
    }

    function updateThreshold(uint256 newThreshold) public onlySelf {
        _updateThreshold(newThreshold);
    }

    function addSignerCredential(
        uint256 signerIndex,
        bytes calldata credential,
        uint256 nonce,
        SignatureWrapper calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encode(signerIndex, credential, nonce));
        _isValidSignleSignerSignature(hash, signature, signerIndex);

        _checkNonceIsReplayable(nonce);
        _addNonce(nonce);

        _addSignerCredential(signerIndex, credential);
    }

    function removeSignerCredential(
        uint256 signerIndex,
        uint256 credentialIndex,
        bytes calldata credential,
        uint256 nonce,
        SignatureWrapper calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encode(signerIndex, credentialIndex, credential, nonce));
        _isValidSignleSignerSignature(hash, signature, signerIndex);

        _checkNonceIsReplayable(nonce);
        _addNonce(nonce);

        _removeSignerCredential(signerIndex, credentialIndex, credential);
    }

    function executeFromOutside(OutsideExecution calldata oe, SignatureWrapper[] calldata signatures)
        public
        payable
        virtual
    {
        _validateOutsideExecution(oe);

        bytes32 hash = DueSmartWalletLib.hash(oe);
        if (!_isValidMultisigSignature(hash, signatures)) revert InvalidSignature(hash, signatures);

        _addNonce(oe.nonce);

        for (uint256 i; i < oe.calls.length; i++) {
            _call(oe.calls[i].target, oe.calls[i].value, oe.calls[i].data);
        }
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        return _isValidSignature(userOpHash, userOp.signature) ? 0 : 1;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable virtual onlyEntryPoint {
        _call(target, value, data);
    }

    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPoint {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        return functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
            || functionSelector == this.addSigner.selector || functionSelector == this.removeSigner.selector
            || functionSelector == this.removeLastSigner.selector || functionSelector == this.updateThreshold.selector;
    }

    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper[] memory signatures = abi.decode(signature, (SignatureWrapper[]));

        return _isValidMultisigSignature(hash, signatures);
    }

    function _isValidMultisigSignature(bytes32 hash, SignatureWrapper[] memory signatures)
        internal
        view
        virtual
        returns (bool)
    {
        if (signatures.length < threshold()) revert NotEnoughSignatures();

        bytes32 safeHash = replaySafeHash(hash);

        bool[] memory seenSignerIndex = new bool[](nextSignerIndex());
        for (uint256 i; i < signatures.length; i++) {
            SignatureWrapper memory signature = signatures[i];

            if (signature.signerIndex >= nextSignerIndex()) {
                revert InvalidSignerIndex(signature.signerIndex);
            }
            if (seenSignerIndex[signature.signerIndex]) {
                revert MultipleSignaturesForSameSigner(signature.signerIndex);
            }
            seenSignerIndex[signature.signerIndex] = true;

            if (!_isValidWrappedSignature(safeHash, signature)) return false;
        }
        return true;
    }

    function _isValidSignleSignerSignature(bytes32 hash, SignatureWrapper memory signature, uint256 expectedSigner)
        internal
        view
        virtual
        returns (bool)
    {
        if (signature.signerIndex != expectedSigner) {
            revert UnexpectedSignerIndex(expectedSigner, signature.signerIndex);
        }

        return _isValidWrappedSignature(replaySafeHash(hash), signature);
    }

    function _isValidWrappedSignature(bytes32 hash, SignatureWrapper memory sigWrapper) internal view returns (bool) {
        bytes memory credential = signerCredentialAtIndex(sigWrapper.signerIndex, sigWrapper.credentialIndex);

        if (credential.length == 32) {
            address signerAddress;
            assembly ("memory-safe") {
                signerAddress := mload(add(credential, 32))
            }
            return SignatureCheckerLib.isValidSignatureNow(signerAddress, hash, sigWrapper.signatureData);
        }

        if (credential.length == 64) {
            (uint256 x, uint256 y) = abi.decode(credential, (uint256, uint256));
            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));
            return WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidCredentialLength(credential);
    }

    function _validateOutsideExecution(OutsideExecution memory oe) internal view {
        if (oe.caller != address(0) && oe.caller != msg.sender) {
            revert CallerMismatch(msg.sender, oe.caller);
        }

        if (oe.executeBefore != 0 && oe.executeBefore < block.timestamp) {
            revert InvalidExecuteBefore(oe.executeBefore, block.timestamp);
        }

        if (oe.executeAfter != 0 && oe.executeAfter > block.timestamp) {
            revert InvalidExecuteAfter(oe.executeAfter, block.timestamp);
        }

        if (oe.chainId != 0) {
            if (oe.chainId != block.chainid) revert InvalidChainId(oe.chainId, block.chainid);
        } else {
            _checkNonceIsReplayable(oe.nonce);

            for (uint256 i; i < oe.calls.length; i++) {
                bytes4 selector = bytes4(oe.calls[i].data);
                if (!canSkipChainIdValidation(selector) || oe.calls[i].target != address(this)) {
                    revert SelectorNotAllowed(selector);
                }
            }
        }
    }

    function _checkNonceIsReplayable(uint256 nonce) private pure {
        uint192 key = uint192(nonce >> 64);
        if (key != REPLAYABLE_NONCE_KEY) revert InvalidNonceKey(key);
    }

    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlySelf {}

    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Due Multisig Wallet", "1");
    }
}
