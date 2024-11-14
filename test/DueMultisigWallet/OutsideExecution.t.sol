// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../src/DueSmartWalletLib.sol";
import {MockTarget} from "../mocks/MockTarget.sol";
import "./DueSmartWalletTestBase.sol";
import "webauthn-sol/../test/Utils.sol";

contract TestOutsideExecution is DueSmartWalletTestBase {
    function testOutsideExecution() public {
        vm.deal(address(account), 1 ether);
        address target = address(new MockTarget());
        bytes memory data = abi.encode(0x12345678);
        Call[] memory calls = new Call[](1);
        calls[0] = Call(target, 123, abi.encodeWithSignature("setData(bytes)", data));

        uint256 nonce = account.nextNonce(0);
        OutsideExecution memory oe = OutsideExecution(address(0x0), nonce, 0x0, 0x0, block.chainid, calls);

        bytes32 toSign = account.replaySafeHash(DueSmartWalletLib.hashOutsideExecution(oe));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);

        DueMultisigWallet.SignatureWrapper[] memory sigs = new DueMultisigWallet.SignatureWrapper[](1);
        sigs[0] = DueMultisigWallet.SignatureWrapper(0, 0, signature);

        account.executeFromOutside(oe, sigs);

        assertEq(MockTarget(target).datahash(), keccak256(data));
        assertEq(target.balance, 123);
    }
}
