// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Multisig} from "../../src/Multisig.sol";

contract MockMultisig is Multisig {
    function init(bytes[] calldata credentials) public {
        addSigner(credentials, 1);
    }

    function addSigner(bytes[] memory credentials, uint256 signersThreshold) public {
        super._addSigner(credentials, signersThreshold);
    }

    function removeSigner(uint256 index, uint256 newThreshold) public {
        super._removeSigner(index, newThreshold);
    }

    function removeLastSigner(uint256 index) public {
        super._removeLastSigner(index);
    }

    function addSignerCredential(uint256 index, bytes memory credential) public {
        super._addSignerCredential(index, credential);
    }

    function removeSignerCredential(uint256 index, uint256 credentialIndex, bytes memory signerCredential) public {
        super._removeSignerCredential(index, credentialIndex, signerCredential);
    }

    function updateThreshold(uint256 newThreshold) public {
        super._updateThreshold(newThreshold);
    }

    function addNonce(uint256 nonce) public {
        super._addNonce(nonce);
    }
}
