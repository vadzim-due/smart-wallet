// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {DueMultisigWallet} from "./DueMultisigWallet.sol";
import {LibClone} from "solady/utils/LibClone.sol";

/// @title Coinbase Smart Wallet Factory
///
/// @notice CoinbaseSmartWallet factory, based on Solady's ERC4337Factory.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337Factory.sol)
contract DueWalletFactory {
    /// @notice Address of the ERC-4337 implementation used as implementation for new accounts.
    address public immutable implementation;

    /// @notice Factory constructor used to initialize the implementation address to use for future
    ///         CoinbaseSmartWallet deployments.
    ///
    /// @param implementation_ The address of the CoinbaseSmartWallet implementation which new accounts will proxy to.
    constructor(address implementation_) payable {
        implementation = implementation_;
    }

    function createAccount(bytes[] calldata credentials, uint256 nonce)
        external
        payable
        virtual
        returns (DueMultisigWallet account)
    {
        (bool alreadyDeployed, address accountAddress) =
            LibClone.createDeterministicERC1967(msg.value, implementation, _getSalt(credentials, nonce));

        account = DueMultisigWallet(payable(accountAddress));

        if (!alreadyDeployed) {
            account.initialize(credentials);
        }
    }

    function getAddress(bytes[] calldata credentials, uint256 nonce) external view returns (address) {
        return LibClone.predictDeterministicAddress(initCodeHash(), _getSalt(credentials, nonce), address(this));
    }

    /// @notice Returns the initialization code hash of the account:
    ///         a ERC1967 proxy that's implementation is `this.implementation`.
    ///
    /// @return The initialization code hash.
    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    /// @notice Returns the create2 salt for `LibClone.predictDeterministicAddress`
    ///
    /// @param credentials Initial signer credentials.
    /// @param nonce  The nonce provided to `createAccount()`.
    ///
    /// @return The computed salt.
    function _getSalt(bytes[] calldata credentials, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(credentials, nonce));
    }
}
