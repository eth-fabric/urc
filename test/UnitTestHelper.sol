// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import "../src/ISlasher.sol";
import { BLS } from "../src/lib/BLS.sol";

contract UnitTestHelper is Test {
    using BLS for *;

    Registry registry;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    // Preset secret keys for deterministic testing
    uint256 constant SECRET_KEY_1 = 12345;
    uint256 constant SECRET_KEY_2 = 67890;

    /// @dev Helper to create a BLS signature for a registration
    function _registrationSignature(uint256 secretKey, address withdrawalAddress, uint16 unregistrationDelay)
        internal
        view
        returns (BLS.G2Point memory)
    {
        bytes memory message = abi.encodePacked(withdrawalAddress, unregistrationDelay);
        return BLS.sign(message, secretKey, registry.DOMAIN_SEPARATOR());
    }

    /// @dev Creates a Registration struct with a real BLS keypair
    function _createRegistration(uint256 secretKey, address withdrawalAddress, uint16 unregistrationDelay)
        internal
        view
        returns (IRegistry.Registration memory)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature = _registrationSignature(secretKey, withdrawalAddress, unregistrationDelay);

        return IRegistry.Registration({ pubkey: pubkey, signature: signature });
    }

    /// @dev Helper to verify operator data matches expected values
    function _assertRegistration(
        bytes32 registrationRoot,
        address expectedWithdrawalAddress,
        uint56 expectedCollateral,
        uint32 expectedRegisteredAt,
        uint32 expectedUnregisteredAt,
        uint16 expectedUnregistrationDelay
    ) internal view {
        (
            address withdrawalAddress,
            uint56 collateral,
            uint32 registeredAt,
            uint32 unregisteredAt,
            uint16 unregistrationDelay
        ) = registry.registrations(registrationRoot);

        assertEq(withdrawalAddress, expectedWithdrawalAddress, "Wrong withdrawal address");
        assertEq(collateral, expectedCollateral, "Wrong collateral amount");
        assertEq(registeredAt, expectedRegisteredAt, "Wrong registration block");
        assertEq(unregisteredAt, expectedUnregisteredAt, "Wrong unregistration block");
        assertEq(unregistrationDelay, expectedUnregistrationDelay, "Wrong unregistration delay");
    }

    function _hashToLeaves(IRegistry.Registration[] memory _registrations) internal pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](_registrations.length);
        for (uint256 i = 0; i < _registrations.length; i++) {
            leaves[i] = keccak256(abi.encode(_registrations[i]));
        }
        return leaves;
    }

    // New helper functions
    function _setupBasicRegistrationParams() internal view returns (uint16 unregistrationDelay, uint256 collateral) {
        unregistrationDelay = uint16(registry.MIN_UNREGISTRATION_DELAY());
        collateral = registry.MIN_COLLATERAL();
    }

    function _setupSingleRegistration(uint256 secretKey, address withdrawalAddr, uint16 unregistrationDelay)
        internal
        view
        returns (IRegistry.Registration[] memory)
    {
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);
        registrations[0] = _createRegistration(secretKey, withdrawalAddr, unregistrationDelay);
        return registrations;
    }

    function _verifySlashingBalances(
        address challenger,
        address operator,
        uint256 slashedAmount,
        uint256 totalCollateral,
        uint256 challengerBalanceBefore,
        uint256 operatorBalanceBefore,
        uint256 urcBalanceBefore
    ) internal view {
        assertEq(challenger.balance, challengerBalanceBefore + slashedAmount, "challenger didn't receive reward");
        assertEq(
            operator.balance,
            operatorBalanceBefore + totalCollateral - slashedAmount,
            "operator didn't receive remaining funds"
        );
        assertEq(address(registry).balance, urcBalanceBefore - totalCollateral, "urc balance incorrect");
    }

    function basicRegistration(uint256 secretKey, uint256 collateral, address withdrawalAddress)
        public
        returns (bytes32 registrationRoot, IRegistry.Registration[] memory registrations)
    {
        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();

        registrations = _setupSingleRegistration(secretKey, withdrawalAddress, unregistrationDelay);

        registrationRoot = registry.register{ value: collateral }(registrations, withdrawalAddress, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            withdrawalAddress,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay
        );
    }

    function signDelegation(uint256 secretKey, ISlasher.Delegation memory delegation, bytes memory domainSeparator)
        public
        view
        returns (ISlasher.SignedDelegation memory)
    {
        BLS.G2Point memory signature = BLS.sign(abi.encode(delegation), secretKey, domainSeparator);
        return ISlasher.SignedDelegation({ delegation: delegation, signature: signature });
    }

    struct RegisterAndDelegateParams {
        uint256 proposerSecretKey;
        uint256 collateral;
        address withdrawalAddress;
        uint256 delegateSecretKey;
        address slasher;
        bytes domainSeparator;
        bytes metadata;
        uint64 validUntil;
    }

    struct RegisterAndDelegateResult {
        bytes32 registrationRoot;
        IRegistry.Registration[] registrations;
        ISlasher.SignedDelegation signedDelegation;
    }

    function registerAndDelegate(RegisterAndDelegateParams memory params)
        public
        returns (RegisterAndDelegateResult memory result)
    {
        // Single registration
        (result.registrationRoot, result.registrations) =
            basicRegistration(params.proposerSecretKey, params.collateral, params.withdrawalAddress);

        // Sign delegation
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposerPubKey: BLS.toPublicKey(params.proposerSecretKey),
            delegatePubKey: BLS.toPublicKey(params.delegateSecretKey),
            slasher: params.slasher,
            validUntil: params.validUntil,
            metadata: params.metadata
        });

        result.signedDelegation = signDelegation(params.proposerSecretKey, delegation, params.domainSeparator);
    }

    function registerAndDelegateReentrant(RegisterAndDelegateParams memory params)
        public
        returns (RegisterAndDelegateResult memory result, address reentrantContractAddress)
    {
        ReentrantSlashCommitment reentrantContract = new ReentrantSlashCommitment(address(registry));

        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();
        result.registrations = _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract), unregistrationDelay);

        // register via reentrant contract
        vm.deal(address(reentrantContract), 100 ether);
        reentrantContract.register(result.registrations, unregistrationDelay);
        result.registrationRoot = reentrantContract.registrationRoot();
        reentrantContractAddress = address(reentrantContract);

        // Sign delegation
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposerPubKey: BLS.toPublicKey(params.proposerSecretKey),
            delegatePubKey: BLS.toPublicKey(params.delegateSecretKey),
            slasher: params.slasher,
            validUntil: params.validUntil,
            metadata: params.metadata
        });

        result.signedDelegation = signDelegation(params.proposerSecretKey, delegation, params.domainSeparator);

        // save info for later reentrancy
        reentrantContract.saveResult(params, result);
    }
}

/// @dev A contract that attempts to register, unregister, and claim collateral via reentrancy
contract ReentrantContract {
    IRegistry public registry;
    bytes32 public registrationRoot;
    uint256 public errors;
    UnitTestHelper.RegisterAndDelegateParams params;
    ISlasher.SignedDelegation signedDelegation;
    IRegistry.Registration[1] registrations;
    uint16 unregistrationDelay;

    constructor(address registryAddress) {
        registry = IRegistry(registryAddress);
    }

    function saveResult(
        UnitTestHelper.RegisterAndDelegateParams memory _params,
        UnitTestHelper.RegisterAndDelegateResult memory _result
    ) public {
        params = _params;
        signedDelegation = _result.signedDelegation;
        for (uint256 i = 0; i < _result.registrations.length; i++) {
            registrations[i] = _result.registrations[i];
        }
    }

    function _hashToLeaves(IRegistry.Registration[] memory _registrations) internal pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](_registrations.length);
        for (uint256 i = 0; i < _registrations.length; i++) {
            leaves[i] = keccak256(abi.encode(_registrations[i]));
        }
        return leaves;
    }

    function register(IRegistry.Registration[] memory _registrations, uint16 _unregistrationDelay) public {
        require(_registrations.length == 1, "test harness supports only 1 registration");
        registrations[0] = _registrations[0];
        unregistrationDelay = _unregistrationDelay;
        registrationRoot = registry.register{ value: 1 ether }(_registrations, address(this), _unregistrationDelay);
    }

    function unregister() public {
        registry.unregister(registrationRoot);
    }

    function claimCollateral() public {
        registry.claimCollateral(registrationRoot);
    }
}

/// @dev A contract that attempts to add collateral, unregister, and claim collateral via reentrancy
contract ReentrantRegistrationContract is ReentrantContract {
    constructor(address registryAddress) ReentrantContract(registryAddress) { }

    receive() external payable {
        try registry.addCollateral{ value: msg.value }(registrationRoot) {
            revert("should not be able to add collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.unregister(registrationRoot) {
            revert("should not be able to unregister");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.claimCollateral(registrationRoot) {
            revert("should not be able to claim collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        // all attempts to re-enter should have failed
        require(errors == 3, "should have 3 errors");
    }
}

/// @dev A contract that attempts to add collateral, unregister, and claim collateral via reentrancy
contract ReentrantSlashableRegistrationContract is ReentrantContract {
    constructor(address registryAddress) ReentrantContract(registryAddress) { }

    receive() external payable {
        try registry.addCollateral{ value: msg.value }(registrationRoot) {
            revert("should not be able to add collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.unregister(registrationRoot) {
            revert("should not be able to unregister");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.claimCollateral(registrationRoot) {
            revert("should not be able to claim collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        bytes32[] memory proof; // empty for single leaf
        try registry.slashRegistration(registrationRoot, registrations[0], proof, 0) {
            revert("should not be able to slash registration again");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        // expected re-registering to succeed
        bytes32 oldRegistrationRoot = registrationRoot;
        IRegistry.Registration[] memory _registrations = new IRegistry.Registration[](1);
        _registrations[0] = registrations[0];
        require(_registrations.length == 1, "test harness supports only 1 registration");
        register(_registrations, unregistrationDelay);

        require(registrationRoot == oldRegistrationRoot, "registration root should not change");

        // previous attempts to re-enter should have failed
        require(errors == 4, "should have 4 errors");
    }
}

/// @dev A contract that attempts to add collateral, unregister, claim collateral, and slash commitment via reentrancy
contract ReentrantSlashCommitment is ReentrantContract {
    constructor(address registryAddress) ReentrantContract(registryAddress) { }

    receive() external payable {
        try registry.addCollateral{ value: msg.value }(registrationRoot) {
            revert("should not be able to add collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.unregister(registrationRoot) {
            revert("should not be able to unregister");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        try registry.claimCollateral(registrationRoot) {
            revert("should not be able to claim collateral");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        // Setup proof
        IRegistry.Registration[] memory _registrations = new IRegistry.Registration[](1);
        _registrations[0] = registrations[0];
        bytes32[] memory leaves = _hashToLeaves(_registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof; // empty for single leaf
        bytes memory evidence;

        try registry.slashCommitment(
            registrationRoot, signedDelegation.signature, proof, leafIndex, signedDelegation, evidence
        ) {
            revert("should not be able to slash commitment again");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        // all attempts to re-enter should have failed
        require(errors == 4, "should have 4 errors");
    }
}
