// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import { BLS } from "../src/lib/BLS.sol";
import {
    UnitTestHelper, ReentrantRegistrationContract, ReentrantSlashableRegistrationContract
} from "./UnitTestHelper.sol";

contract RegistryTest is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_register() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        basicRegistration(SECRET_KEY_1, collateral, operator);
    }

    function test_register_insufficientCollateral() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        vm.expectRevert(IRegistry.InsufficientCollateral.selector);
        registry.register{ value: minCollateral - 1 }(registrations, operator, unregistrationDelay);
    }

    function test_register_unregistrationDelayTooShort() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            operator,
            unregistrationDelay // delay that is signed by validator key
        );

        vm.expectRevert(IRegistry.UnregistrationDelayTooShort.selector);
        registry.register{ value: minCollateral }(
            registrations,
            operator,
            unregistrationDelay - 1 // submit shorter delay than the one signed by validator key
        );
    }

    function test_register_OperatorAlreadyRegistered() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot =
            registry.register{ value: minCollateral }(registrations, operator, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            operator,
            uint56(minCollateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        // Attempt duplicate registration
        vm.expectRevert(IRegistry.OperatorAlreadyRegistered.selector);
        registry.register{ value: minCollateral }(registrations, operator, unregistrationDelay);
    }

    function test_verifyMerkleProofHeight1() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot =
            registry.register{ value: minCollateral }(registrations, operator, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            operator,
            uint56(minCollateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 gotCollateral = registry.verifyMerkleProof(
            registrationRoot,
            leaves[0],
            proof,
            0 // leafIndex
        );
        assertEq(gotCollateral, uint56(minCollateral / 1 gwei), "Wrong collateral amount");
    }

    function test_slashRegistrationHeight1_DifferentUnregDelay() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(
            SECRET_KEY_1,
            operator,
            unregistrationDelay // delay that is signed by validator key
        );

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            operator,
            unregistrationDelay + 1 // submit different delay
        );

        _assertRegistration(
            registrationRoot,
            operator,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay + 1,
            0
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(challenger);
        uint256 rewardCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, 0);
        assertEq(rewardCollateralWei, minCollateral, "Wrong rewardCollateralWei amount");

        _verifySlashingBalances(
            challenger,
            operator,
            0,
            rewardCollateralWei,
            collateral,
            challengerBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );

        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0, 0);
    }

    function test_slashRegistrationHeight1_DifferentOwner() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(
            SECRET_KEY_1,
            operator, // withdrawal that is signed by validator key
            unregistrationDelay
        );

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief, // thief tries to frontrun operator by setting his address as withdrawal address
            unregistrationDelay
        );

        _assertRegistration(
            registrationRoot,
            thief, // confirm thief's address is what was registered
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 thiefBalanceBefore = thief.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(operator);
        uint256 rewardCollateralWei = registry.slashRegistration(
            registrationRoot,
            registrations[0],
            proof,
            0 // leafIndex
        );

        _verifySlashingBalances(
            operator,
            thief,
            0,
            rewardCollateralWei,
            collateral,
            thiefBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );

        // ensure operator was deleted
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0, 0);
    }

    function test_verifyMerkleProofHeight2() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            operator,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test first proof path
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[0], proof, leafIndex);
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");

        // Test second proof path
        leafIndex = 1;
        proof = MerkleTree.generateProof(leaves, leafIndex);
        gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[1], proof, leafIndex);
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
    }

    function test_slashRegistrationHeight2_DifferentUnregDelay() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);
        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            operator,
            unregistrationDelay + 1 // submit different delay than the one signed by validator key
        );

        console.log("registrationRoot");
        console.logBytes32(registrationRoot);

        // Verify initial registration state
        _assertRegistration(
            registrationRoot,
            operator,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay + 1, // confirm different delay
            0
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        uint256 operatorBalanceBefore = operator.balance;
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(challenger);
        uint256 rewardCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, leafIndex);

        _verifySlashingBalances(
            challenger,
            operator,
            0,
            rewardCollateralWei,
            collateral,
            challengerBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );
    }

    function test_slashRegistrationHeight2_DifferentOwner() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);
        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_2, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief, // thief tries to frontrun operator by setting his address as withdrawal address
            unregistrationDelay
        );

        // Verify initial registration state
        _assertRegistration(
            registrationRoot,
            thief,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        // Create proof for operator's registration
        bytes32[] memory leaves = _hashToLeaves(registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        uint256 thiefBalanceBefore = thief.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(operator);
        uint256 rewardCollateralWei = registry.slashRegistration(registrationRoot, registrations[0], proof, leafIndex);

        _verifySlashingBalances(
            operator,
            thief,
            0,
            rewardCollateralWei,
            collateral,
            thiefBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );
    }

    function test_verifyMerkleProofHeight3() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 3 * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](3); // will be padded to 4

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        registrations[1] = _createRegistration(SECRET_KEY_1 + 1, operator, unregistrationDelay);

        registrations[2] = _createRegistration(SECRET_KEY_1 + 2, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        _assertRegistration(
            registrationRoot,
            operator,
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[i], proof, i);
            assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
        }
    }

    function test_fuzzRegister(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = size * minCollateral;

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, operator, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[i], proof, i);
            assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
        }
    }

    function test_slashRegistrationFuzz_DifferentUnregDelay(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, operator, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: minCollateral }(
            registrations,
            operator,
            unregistrationDelay + 1 // submit different delay than the one signed by validator keys
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        uint256 thiefBalanceBefore = thief.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            vm.startPrank(operator);
            registry.slashRegistration(registrationRoot, registrations[i], proof, i);
            _verifySlashingBalances(
                operator,
                thief,
                0,
                minCollateral,
                minCollateral,
                thiefBalanceBefore,
                operatorBalanceBefore,
                urcBalanceBefore
            );

            _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0, 0);

            // Re-register to reset the state
            registrationRoot = registry.register{ value: minCollateral }(
                registrations,
                operator,
                unregistrationDelay + 1 // submit different delay than the one signed by validator keys
            );

            // update balances
            thiefBalanceBefore = thief.balance;
            operatorBalanceBefore = operator.balance;
            urcBalanceBefore = address(registry).balance;
        }
    }

    function test_slashRegistrationFuzz_DifferentOwner(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, operator, unregistrationDelay);
        }

        bytes32 registrationRoot = registry.register{ value: minCollateral }(
            registrations,
            thief, // submit different withdrawal address than the one signed by validator keys
            unregistrationDelay
        );

        bytes32[] memory leaves = _hashToLeaves(registrations);

        uint256 thiefBalanceBefore = thief.balance;
        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            vm.startPrank(operator);
            registry.slashRegistration(registrationRoot, registrations[i], proof, i);
            _verifySlashingBalances(
                operator,
                thief,
                0,
                minCollateral,
                minCollateral,
                thiefBalanceBefore,
                operatorBalanceBefore,
                urcBalanceBefore
            );

            _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0, 0);

            // Re-register to reset the state
            registrationRoot = registry.register{ value: minCollateral }(
                registrations,
                thief, // submit different withdrawal address than the one signed by validator keys
                unregistrationDelay
            );

            // update balances
            thiefBalanceBefore = thief.balance;
            operatorBalanceBefore = operator.balance;
            urcBalanceBefore = address(registry).balance;
        }
    }

    function test_unregister() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorUnregistered(registrationRoot, uint32(block.number));
        registry.unregister(registrationRoot);

        IRegistry.Operator memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.unregisteredAt, uint32(block.number), "Wrong unregistration block");
        assertEq(operatorData.registeredAt, uint32(block.number), "Wrong registration block"); // Should remain unchanged
    }

    function test_unregister_wrongOperator() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        // thief tries to unregister operator's registration
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.unregister(registrationRoot);
    }

    function test_unregister_alreadyUnregistered() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Try to unregister again
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.AlreadyUnregistered.selector);
        registry.unregister(registrationRoot);
    }

    function test_claimCollateral() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Wait for unregistration delay
        vm.roll(block.number + unregistrationDelay);

        uint256 balanceBefore = operator.balance;

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(registrationRoot, uint256(collateral / 1 gwei));
        registry.claimCollateral(registrationRoot);

        assertEq(operator.balance, balanceBefore + collateral, "Collateral not returned");

        // Verify registration was deleted
        IRegistry.Operator memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.owner, address(0), "Registration not deleted");
    }

    function test_claimCollateral_notUnregistered() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        // Try to claim without unregistering first
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.NotUnregistered.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_delayNotMet() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Try to claim before delay has passed
        vm.roll(block.number + unregistrationDelay - 1);

        vm.startPrank(operator);
        vm.expectRevert(IRegistry.UnregistrationDelayNotMet.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_alreadyClaimed() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        vm.roll(block.number + unregistrationDelay);

        vm.startPrank(operator);
        registry.claimCollateral(registrationRoot);

        // Try to claim again
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.NoCollateralToClaim.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_addCollateral(uint56 addAmount) public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;
        vm.assume((addAmount + collateral) / 1 gwei < uint256(2 ** 56));

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        uint256 expectedCollateralGwei = (collateral + addAmount) / 1 gwei;
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectEmit(address(registry));
        emit IRegistry.CollateralAdded(registrationRoot, expectedCollateralGwei);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        IRegistry.Operator memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.collateralGwei, expectedCollateralGwei, "Collateral not added");
    }

    function test_addCollateral_overflow() public {
        (uint16 unregistrationDelay, uint256 minCollateral) = _setupBasicRegistrationParams();
        uint256 collateral = 2 * minCollateral;

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator, unregistrationDelay);

        uint256 addAmount = 2 ** 56 * 1 gwei; // overflow uint56
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectRevert(IRegistry.CollateralOverflow.selector);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        IRegistry.Operator memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.collateralGwei, uint56(collateral / 1 gwei), "Collateral should not be changed");
    }

    function test_addCollateral_notRegistered() public {
        bytes32 registrationRoot = bytes32(uint256(0));
        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.addCollateral{ value: 1 gwei }(registrationRoot);
    }

    // For setup we register() -> unregister() -> claimCollateral()
    // The registration's withdrawal address is the reentrant contract
    // Claiming collateral causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral()
    // The test succeeds because the reentract contract catches the errors
    function test_reentrantClaimCollateral() public {
        ReentrantRegistrationContract reentrantContract = new ReentrantRegistrationContract(address(registry));
        vm.deal(address(reentrantContract), 1000 ether);

        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract), unregistrationDelay);

        reentrantContract.register(registrations, unregistrationDelay);

        // pretend to unregister
        reentrantContract.unregister();

        // wait for unregistration delay
        vm.roll(block.number + unregistrationDelay);

        uint256 balanceBefore = address(reentrantContract).balance;

        vm.prank(address(reentrantContract));
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(reentrantContract.registrationRoot(), reentrantContract.collateral() / 1 gwei);

        // initiate reentrancy
        reentrantContract.claimCollateral();

        assertEq(
            address(reentrantContract).balance,
            balanceBefore + reentrantContract.collateral(),
            "Collateral not returned"
        );

        // Verify registration was deleted
        IRegistry.Operator memory operatorData = getRegistrationData(reentrantContract.registrationRoot());
        assertEq(operatorData.owner, address(0), "Registration not deleted");
    }

    // For setup we register() -> slashRegistration()
    // The registration's withdrawal address is the reentrant contract
    // Triggering a slash causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral(), slashRegistration()
    // Finally it re-registers and the registration root should not change
    // The test succeeds because the reentract contract catches the errors
    function test_reentrantSlashRegistration() public {
        ReentrantSlashableRegistrationContract reentrantContract =
            new ReentrantSlashableRegistrationContract(address(registry));
        vm.deal(address(reentrantContract), 1000 ether);

        (uint16 unregistrationDelay,) = _setupBasicRegistrationParams();
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator, unregistrationDelay);

        // frontrun to set withdrawal address to reentrantContract
        reentrantContract.register(registrations, unregistrationDelay);

        _assertRegistration(
            reentrantContract.registrationRoot(),
            address(reentrantContract),
            uint56(reentrantContract.collateral() / 1 gwei),
            uint32(block.number),
            type(uint32).max,
            unregistrationDelay,
            0
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // operator can slash the registration
        vm.startPrank(operator);
        registry.slashRegistration(
            reentrantContract.registrationRoot(),
            registrations[0],
            proof,
            0 // leafIndex
        );
    }
}
