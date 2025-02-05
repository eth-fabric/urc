// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import "../src/ISlasher.sol";
import { BLS } from "../src/lib/BLS.sol";

contract UnitTestHelper is Test {
    using BLS for *;

    Registry registry;
    address operator = makeAddr("operator");
    address challenger = makeAddr("challenger");
    address delegate = makeAddr("delegate");
    address thief = makeAddr("thief");

    // Preset secret keys for deterministic testing
    uint256 constant SECRET_KEY_1 = 12345;
    uint256 constant SECRET_KEY_2 = 67890;

    /// @dev Helper to create a BLS signature for a registration
    function _registrationSignature(uint256 secretKey, address owner) internal view returns (BLS.G2Point memory) {
        bytes memory message = abi.encode(owner);
        return BLS.sign(message, secretKey, registry.REGISTRATION_DOMAIN_SEPARATOR());
    }

    /// @dev Creates a Registration struct with a real BLS keypair
    function _createRegistration(uint256 secretKey, address owner)
        internal
        view
        returns (IRegistry.Registration memory)
    {
        BLS.G1Point memory pubkey = BLS.toPublicKey(secretKey);
        BLS.G2Point memory signature = _registrationSignature(secretKey, owner);

        return IRegistry.Registration({ pubkey: pubkey, signature: signature });
    }

    /// @dev Helper to verify operator data matches expected values
    function _assertRegistration(
        bytes32 registrationRoot,
        address expectedowner,
        uint56 expectedCollateral,
        uint32 expectedRegisteredAt,
        uint32 expectedUnregisteredAt,
        uint32 expectedSlashedAt
    ) internal view {
        OperatorData memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.owner, expectedowner, "Wrong withdrawal address");
        assertEq(operatorData.collateralGwei, expectedCollateral, "Wrong collateral amount");
        assertEq(operatorData.registeredAt, expectedRegisteredAt, "Wrong registration block");
        assertEq(operatorData.unregisteredAt, expectedUnregisteredAt, "Wrong unregistration block");
        assertEq(operatorData.slashedAt, expectedSlashedAt, "Wrong slashed block");
    }

    function _hashToLeaves(IRegistry.Registration[] memory _registrations) internal pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](_registrations.length);
        for (uint256 i = 0; i < _registrations.length; i++) {
            leaves[i] = keccak256(abi.encode(_registrations[i]));
        }
        return leaves;
    }

    function _setupSingleRegistration(uint256 secretKey, address owner)
        internal
        view
        returns (IRegistry.Registration[] memory)
    {
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);
        registrations[0] = _createRegistration(secretKey, owner);
        return registrations;
    }

    function _verifySlashingBalances(
        address _challenger,
        address _operator,
        uint256 _slashedAmount,
        uint256 _rewardAmount,
        uint256 _totalCollateral,
        uint256 _challengerBalanceBefore,
        uint256 _operatorBalanceBefore,
        uint256 _urcBalanceBefore
    ) internal view {
        assertEq(_challenger.balance, _challengerBalanceBefore + _rewardAmount, "challenger didn't receive reward");
        assertEq(
            _operator.balance,
            _operatorBalanceBefore + _totalCollateral - _slashedAmount - _rewardAmount,
            "operator didn't receive remaining funds"
        );
        assertEq(address(registry).balance, _urcBalanceBefore - _totalCollateral, "urc balance incorrect");
    }

    function _verifySlashCommitmentBalances(
        address _challenger,
        uint256 _slashedAmount,
        uint256 _rewardAmount,
        uint256 _challengerBalanceBefore,
        uint256 _urcBalanceBefore
    ) internal view {
        assertEq(_challenger.balance, _challengerBalanceBefore + _rewardAmount, "challenger didn't receive reward");
        assertEq(address(registry).balance, _urcBalanceBefore - _slashedAmount - _rewardAmount, "urc balance incorrect");
    }

    struct OperatorData {
        address owner;
        uint56 collateralGwei;
        uint8 numKeys;
        uint32 registeredAt;
        uint32 unregisteredAt;
        uint32 slashedAt;
    }

    function getRegistrationData(bytes32 registrationRoot) public view returns (OperatorData memory) {
        (
            address owner,
            uint56 collateralGwei,
            uint8 numKeys,
            uint32 registeredAt,
            uint32 unregisteredAt,
            uint32 slashedAt
        ) = registry.registrations(registrationRoot);

        return OperatorData({
            owner: owner,
            collateralGwei: collateralGwei,
            numKeys: numKeys,
            registeredAt: registeredAt,
            unregisteredAt: unregisteredAt,
            slashedAt: slashedAt
        });
    }

    function basicRegistration(uint256 secretKey, uint256 collateral, address owner)
        public
        returns (bytes32 registrationRoot, IRegistry.Registration[] memory registrations)
    {
        registrations = _setupSingleRegistration(secretKey, owner);

        registrationRoot = registry.register{ value: collateral }(registrations, owner);

        _assertRegistration(
            registrationRoot, owner, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
        );
    }

    function basicCommitment(uint256 secretKey, address slasher, bytes memory payload)
        public
        pure
        returns (ISlasher.SignedCommitment memory signedCommitment)
    {
        ISlasher.Commitment memory commitment =
            ISlasher.Commitment({ commitmentType: 0, payload: payload, slasher: slasher });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(secretKey, keccak256(abi.encode(commitment)));
        bytes memory signature = abi.encodePacked(r, s, v);
        signedCommitment = ISlasher.SignedCommitment({ commitment: commitment, signature: signature });
    }

    function signDelegation(uint256 secretKey, ISlasher.Delegation memory delegation)
        public
        view
        returns (ISlasher.SignedDelegation memory)
    {
        BLS.G2Point memory signature =
            BLS.sign(abi.encode(delegation), secretKey, registry.DELEGATION_DOMAIN_SEPARATOR());
        return ISlasher.SignedDelegation({ delegation: delegation, signature: signature });
    }

    struct RegisterAndDelegateParams {
        uint256 proposerSecretKey;
        uint256 collateral;
        address owner;
        uint256 delegateSecretKey;
        uint256 committerSecretKey;
        address committer;
        address slasher;
        bytes metadata;
        uint64 slot;
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
            basicRegistration(params.proposerSecretKey, params.collateral, params.owner);

        // Sign delegation
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: params.metadata
        });

        result.signedDelegation = signDelegation(params.proposerSecretKey, delegation);
    }

    function registerAndDelegateReentrant(RegisterAndDelegateParams memory params)
        public
        returns (RegisterAndDelegateResult memory result, address reentrantContractAddress)
    {
        ReentrantSlashEquivocation reentrantContract = new ReentrantSlashEquivocation(address(registry));

        result.registrations = _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract));

        // register via reentrant contract
        vm.deal(address(reentrantContract), 100 ether);
        reentrantContract.register(result.registrations);
        result.registrationRoot = reentrantContract.registrationRoot();
        reentrantContractAddress = address(reentrantContract);

        // Sign delegation
        ISlasher.Delegation memory delegation = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: params.metadata
        });

        result.signedDelegation = signDelegation(params.proposerSecretKey, delegation);

        // Sign a second delegation to equivocate
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });
        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // save info for later reentrancy
        reentrantContract.saveResult(params, result, signedCommitment, signedDelegationTwo);
    }
}

contract IReentrantContract {
    uint256 public collateral;
}

/// @dev A contract that attempts to register, unregister, and claim collateral via reentrancy
contract ReentrantContract {
    IRegistry public registry;
    uint256 public collateral = 2 ether;
    bytes32 public registrationRoot;
    uint256 public errors;
    UnitTestHelper.RegisterAndDelegateParams params;
    ISlasher.SignedDelegation signedDelegation;
    IRegistry.Registration[1] registrations;
    uint16 unregistrationDelay;

    ISlasher.SignedCommitment signedCommitment;
    ISlasher.SignedDelegation signedDelegationTwo;

    constructor(address registryAddress) {
        registry = IRegistry(registryAddress);
    }

    function saveResult(
        UnitTestHelper.RegisterAndDelegateParams memory _params,
        UnitTestHelper.RegisterAndDelegateResult memory _result,
        ISlasher.SignedCommitment memory _signedCommitment,
        ISlasher.SignedDelegation memory _signedDelegationTwo
    ) public {
        params = _params;
        signedDelegation = _result.signedDelegation;
        for (uint256 i = 0; i < _result.registrations.length; i++) {
            registrations[i] = _result.registrations[i];
        }
        signedCommitment = _signedCommitment;
        signedDelegationTwo = _signedDelegationTwo;
    }

    function _hashToLeaves(IRegistry.Registration[] memory _registrations) internal pure returns (bytes32[] memory) {
        bytes32[] memory leaves = new bytes32[](_registrations.length);
        for (uint256 i = 0; i < _registrations.length; i++) {
            leaves[i] = keccak256(abi.encode(_registrations[i]));
        }
        return leaves;
    }

    function register(IRegistry.Registration[] memory _registrations) public {
        require(_registrations.length == 1, "test harness supports only 1 registration");
        registrations[0] = _registrations[0];
        registrationRoot = registry.register{ value: collateral }(_registrations, address(this));
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
        register(_registrations);

        require(registrationRoot == oldRegistrationRoot, "registration root should not change");

        // previous attempts to re-enter should have failed
        require(errors == 4, "should have 4 errors");
    }
}

/// @dev A contract that attempts to add collateral, unregister, claim collateral, and slash commitment via reentrancy
contract ReentrantSlashEquivocation is ReentrantContract {
    constructor(address registryAddress) ReentrantContract(registryAddress) { }

    receive() external payable {
        try registry.addCollateral{ value: msg.value }(registrationRoot) {
            revert("should not be able to add collateral");
        } catch (bytes memory _reason) {
            revert("should not be able to add collateral");
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
        uint256 leafIndex = 0;
        bytes32[] memory proof; // empty for single leaf
        bytes memory evidence;

        try registry.slashEquivocation(
            registrationRoot, signedDelegation.signature, proof, leafIndex, signedDelegation, signedDelegationTwo
        ) {
            revert("should not be able to slash equivocation again");
        } catch (bytes memory _reason) {
            errors += 1;
        }

        // all attempts to re-enter should have failed
        require(errors == 4, "should have 4 errors");
    }
}
