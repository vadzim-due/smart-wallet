// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {DueMultisigWallet, DueWalletFactory} from "../src/DueWalletFactory.sol";

contract DeployFactoryScript is Script {
    // address constant EXPECTED_IMPLEMENTATION = 0xC53Bf6B72AfA99e5c01D4bEFC2B1a00340BBF3b8;
    // address constant EXPECTED_FACTORY = 0xaA5AfBC422d563292F62733FC92422F53Ec548Ac;

    function run() public {
        console2.log("Deploying on chain ID", block.chainid);
        address implementation = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(DueMultisigWallet).creationCode,
            salt: 0x3438ae5ce1ff7750c1e09c4b28e2a04525da412f91561eb5b57729977f591fbb
        });
        console2.log("implementation", implementation);
        // assert(implementation == EXPECTED_IMPLEMENTATION);
        address factory = SafeSingletonDeployer.broadcastDeploy({
            creationCode: type(DueWalletFactory).creationCode,
            args: abi.encode(implementation),
            salt: 0x278d06dab87f67bb2d83470a70c8975a2c99872f290058fb43bcc47da5f0390c
        });
        console2.log("factory", factory);
        // assert(factory == EXPECTED_FACTORY);
    }
}
