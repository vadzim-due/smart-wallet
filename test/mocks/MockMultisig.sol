// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Credential, CredentialType} from "../../src/DueSmartWalletLib.sol";
import {Multisig} from "../../src/Multisig.sol";

contract MockMultisig is Multisig {
    function init(Credential[] calldata credentials) public {
        addSigner(credentials, 1);
    }

    function addSigner(Credential[] memory credentials, uint256 signersThreshold) public {
        super._addSigner(credentials, signersThreshold);
    }

    function removeSigner(uint256 index, uint256 newThreshold) public {
        super._removeSigner(index, newThreshold);
    }

    function removeLastSigner(uint256 index) public {
        super._removeLastSigner(index);
    }

    function addSignerCredential(uint256 index, Credential memory credential) public {
        super._addSignerCredential(index, credential);
    }

    function removeSignerCredential(uint256 index, uint256 credentialIndex, Credential memory signerCredential)
        public
    {
        super._removeSignerCredential(index, credentialIndex, signerCredential);
    }

    function updateThreshold(uint256 newThreshold) public {
        super._updateThreshold(newThreshold);
    }

    function addNonce(uint256 nonce) public {
        super._addNonce(nonce);
    }
}
