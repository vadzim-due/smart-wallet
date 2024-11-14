deploy :; source .env && export FOUNDRY_PROFILE=deploy && forge script script/DeployFactory.s.sol --rpc-url $${RPC_URL}  --account $${ACCOUNT} --broadcast --verify

deploy-due :; source .env && export FOUNDRY_PROFILE=deploy && forge script script/DueDeployFactory.s.sol --rpc-url $${RPC_URL}  --account $${ACCOUNT} --broadcast --verify
