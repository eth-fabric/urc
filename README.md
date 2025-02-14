# Universal Registry Contract

**These standards are currently under review / feedback and are not audited.**

The URC is a universal contract for… 
- anyone to **register** for proposer commitments
- anyone to **slash** proposers that break commitments

it should…
- be governance-free and immutable
- be simple and maximally expressive
- use ETH as collateral
- not rely on any external contracts
- minimize switching costs
- be gas-efficient
- be open-source


### Usage
The URC is written using Foundry. To install:
```
curl -L https://foundry.paradigm.xyz | bash
```

To run the tests:
```
forge build
forge test
```

### Design
See the [docs](./docs/overview.md) for more information.

### Examples
See the [examples](./example/README.md) for reference implementations of Slasher contracts.

### References
- Justin Drake’s proposed requirements
    > 1. The contract is super simple and short (ideally ~100 lines).
    > 2. Only ETH for deposits.
    > 3. All the constants are parametrised (so as to minimise bike shedding for now).
    > 4. Slashing (and delegation) logic is encapsulated by pieces of signed EVM bytecode shared offchain between relevant parties (eg users and gateways). This is for maximum credible neutrality, forward compatibility, simplicity, and gas efficiency.
    > 5. No dependence on any external code (especially restaking platforms).
    > 6. Zero governance, fully immutable.
    > 7. Open source from day 1, Apache 2.0 + MIT dual licensing.
    > 8. Nice to have: support for underwriters
    > 9. Nice to have: bootstrapping phase with freeze instead of burn
    > 10. Code is maintained in a neutral Github org.
- [mteam’s writeup on the registry](https://hackmd.io/@mteam/unfiedpreconfregistry)
- [UniFi’s registry implementation](https://github.com/PufferFinance/UniFi/blob/main/l1-contracts/src/UniFiAVSManager.sol)
- [Nethermind/Taiko’s registry implementation](https://github.com/NethermindEth/taiko-Preconf-AVS/)
- [Jason's URC implementation from Sequencing Week](https://github.com/PufferFinance/preconfs)
- [Paradigm's solidity implementation of BLS12-381 using Pectra BLS precompiles](https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol)
- [Jason's Sequencing week presentation](https://docs.google.com/presentation/d/1-iuKIMwV9lxw4BBdhHL3_hWDysTWOWS-lWPpCmDvl6g/edit#slide=id.g3131bf307dc_0_67)
- [Jason's Sequencing Day presentation](https://docs.google.com/presentation/d/1aR1iY4bcRc3RApAt2xx1gV7DEqcEQZZd0rgMo3ozXC0/edit#slide=id.p)

### License
MIT + Apache-2.0
