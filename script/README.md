# Script Usage

Example environment variable values are found in [`.env`](./.env). The scripts assume your EOA is a keystore accessible via the `--account` flag, see [`cast wallet`](https://book.getfoundry.sh/reference/cli/cast/wallet) for more info.

## Core URC Admin functions
### Deploying `Registry.sol`
```bash
forge script script/Deploy.s.sol:DeployScript --sig "deploy()" --rpc-url $RPC_URL --account $FOUNDRY_WALLET --broadcast
```

### Generating dummy registrations
-THIS SCRIPT IS NOT MEANT FOR PRODUCTION- it is useful for testing the URC functions. 

Running this script will generate `N` `SignedRegistration` messages signed by deterministic BLS private keys. The `SignedRegistrations` will be saved to `script/output/{$SIGNED_REGISTRATIONS_FILE}` following the template file [SignedRegistrations.json](./output/SignedRegistrations.json).
```bash
forge script script/Register.s.sol:RegisterScript --sig "nDummyRegistrations(uint256,address,string)" $N $OWNER $SIGNED_REGISTRATIONS_FILE
```
### Registering to the URC
Running this script will call `register()` using the supplied `SignedRegistrations` located in `script/output/{$SIGNED_REGISTRATIONS_FILE}` following the template file [SignedRegistrations.json](./output/SignedRegistrations.json). `$COLLATERAL` wei will be transfered from the caller's account to the URC.
```bash
forge script script/Register.s.sol:RegisterScript --sig "register(address,uint256,string)" $REGISTRY_ADDRESS $COLLATERAL $SIGNED_REGISTRATIONS_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
```

### Unregistering from the URC
Running this script will call `unregister()` using the `$REGISTRATION_ROOT`. It's required that the caller is the registered `owner` address.
```bash
forge script script/Register.s.sol:RegisterScript --sig "unregister(address,bytes32)" $REGISTRY_ADDRESS $REGISTRATION_ROOT --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
```

### Opting into a Slasher
Running this script will call `optInToSlasher()` for the specified `$REGISTRATION_ROOT`. The caller must be the registered operator's `owner` address.

```bash
forge script script/OptInAndOut.s.sol:OptInAndOutScript --sig "optInToSlasher(address,bytes32,address,address)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $SLASHER $COMMITTER --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
```

### Opting out of a Slasher
Running this script will call `optOutOfSlasher()` for the specified `$REGISTRATION_ROOT`. The caller must be the registered operator's owner address.

```bash
forge script script/OptInAndOut.s.sol:OptInAndOutScript --sig "optOutOfSlasher(address,bytes32,address)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $SLASHER --account $FOUNDRY_WALLET --rpc-url $RPC_URL --broadcast
```

## URC Slashing functions

## URC Utility functions

### getConfig
Retrieves the configuration of the URC and writes it to `script/output/{$CONFIG_FILE}` following the template file [`Config.json`](./output/Config.json).

```bash
forge script script/Getters.s.sol:GettersScript --sig "getConfig(address,string)" $REGISTRY_ADDRESS $CONFIG_FILE --rpc-url $RPC_URL
```

### getOperatorData
Given a `$REGISTRATION_ROOT`, the script will write the `OperatorData` to `script/output/{$OPERATOR_DATA_FILE}` following the template file [`OperatorData.json`](./output/OperatorData.json).

```bash
forge script script/Getters.s.sol:GettersScript --sig "getOperatorData(address,bytes32,string)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $OPERATOR_DATA_FILE --rpc-url $RPC_URL
```

### getRegistrationProof
Given a compressed 48-byte-hex-encoded BLS `$PUBKEY` and a `SignedRegistrations` file located in `script/output/{$SIGNED_REGISTRATIONS_FILE}`, the script will write the `RegistrationProof` for the specified pubkey to `script/output/{$REGISTRATION_PROOF_FILE}` following the template file [`RegistrationProof.json`](./output/RegistrationProof.json).

```bash
forge script script/Getters.s.sol:GettersScript --sig "getRegistrationProof(address,bytes,string,string)" $REGISTRY_ADDRESS $PUBKEY $SIGNED_REGISTRATIONS_FILE $REGISTRATION_PROOF_FILE --account $FOUNDRY_WALLET --rpc-url $RPC_URL
```

### getSlasherCommitment
Given a `$REGISTRATION_ROOT` and `$SLASHER_ADDRESS`, the script will write the `SlasherCommitment` data to `script/output/{$SLASHER_COMMITMENT_FILE}` following the template file [`SlasherCommitment.json`](./output/SlasherCommitment.json).

```bash
forge script script/Getters.s.sol:GettersScript --sig "getSlasherCommitment(address,bytes32,address,string)" $REGISTRY_ADDRESS $REGISTRATION_ROOT $SLASHER $SLASHER_COMMITMENT_FILE --rpc-url $RPC_URL
```

