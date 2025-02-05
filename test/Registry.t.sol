// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Registry.sol";
import "../src/IRegistry.sol";
import { BLS } from "../src/lib/BLS.sol";
import {
    UnitTestHelper, ReentrantRegistrationContract, ReentrantSlashableRegistrationContract
} from "./UnitTestHelper.sol";

contract RegisterTester is UnitTestHelper {
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
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        vm.expectRevert(IRegistry.InsufficientCollateral.selector);
        registry.register{ value: collateral - 1 }(registrations, operator);
    }

    function test_register_OperatorAlreadyRegistered() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(
            registrationRoot, operator, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
        );

        // Attempt duplicate registration
        vm.expectRevert(IRegistry.OperatorAlreadyRegistered.selector);
        registry.register{ value: collateral }(registrations, operator);
    }

    function test_verifyMerkleProofHeight1() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(
            registrationRoot, operator, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
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
        assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
    }

    function test_verifyMerkleProofHeight2() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createRegistration(SECRET_KEY_2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(
            registrationRoot, operator, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
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

    function test_verifyMerkleProofHeight3() public {
        uint256 collateral = 3 * registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](3); // will be padded to 4

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createRegistration(SECRET_KEY_1 + 1, operator);

        registrations[2] = _createRegistration(SECRET_KEY_1 + 2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(
            registrationRoot, operator, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
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
        uint256 collateral = size * registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, operator);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        bytes32[] memory leaves = _hashToLeaves(registrations);

        // Test all proof paths
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32[] memory proof = MerkleTree.generateProof(leaves, i);
            uint256 gotCollateral = registry.verifyMerkleProof(registrationRoot, leaves[i], proof, i);
            assertEq(gotCollateral, uint56(collateral / 1 gwei), "Wrong collateral amount");
        }
    }
}

contract UnregisterTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_unregister() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorUnregistered(registrationRoot, uint32(block.number));
        registry.unregister(registrationRoot);

        OperatorData memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.unregisteredAt, uint32(block.number), "Wrong unregistration block");
        assertEq(operatorData.registeredAt, uint32(block.number), "Wrong registration block"); // Should remain unchanged
    }

    function test_unregister_wrongOperator() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        // thief tries to unregister operator's registration
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.unregister(registrationRoot);
    }

    function test_unregister_alreadyUnregistered() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Try to unregister again
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.AlreadyUnregistered.selector);
        registry.unregister(registrationRoot);
    }
}

contract OptInAndOutTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_optInAndOut() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address committer = address(1234);
        address slasher = address(5678);

        // Wait for opt-in delay
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW());

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorOptedIn(registrationRoot, slasher, committer);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Wait for opt-in delay
        vm.roll(block.number + registry.OPT_IN_DELAY());

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorOptedOut(registrationRoot, slasher);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }

    function test_optInToSlasher_wrongOperator() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW());

        // Try to opt in from wrong address
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.optInToSlasher(registrationRoot, slasher, committer);
    }

    function test_optInToSlasher_alreadyOptedIn() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW());

        // First opt-in
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt in again
        vm.expectRevert(IRegistry.AlreadyOptedIn.selector);
        registry.optInToSlasher(registrationRoot, slasher, committer);
    }

    function test_optOutOfSlasher_wrongOperator() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW());

        // Opt in first
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt out from wrong address
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }

    function test_optOutOfSlasher_optInDelayNotMet() public {
        uint256 collateral = registry.MIN_COLLATERAL();
        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW());

        // Opt in
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt out before delay
        vm.roll(block.number + registry.OPT_IN_DELAY() - 1);
        vm.expectRevert(IRegistry.OptInDelayNotMet.selector);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }
}

contract ClaimCollateralTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_claimCollateral() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Wait for unregistration delay
        vm.roll(block.number + registry.UNREGISTRATION_DELAY());

        uint256 balanceBefore = operator.balance;

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(registrationRoot, uint256(collateral / 1 gwei));
        registry.claimCollateral(registrationRoot);

        assertEq(operator.balance, balanceBefore + collateral, "Collateral not returned");

        // Verify registration was deleted
        OperatorData memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.owner, address(0), "Registration not deleted");
    }

    function test_claimCollateral_notUnregistered() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        // Try to claim without unregistering first
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.NotUnregistered.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_delayNotMet() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Try to claim before delay has passed
        vm.roll(block.number + registry.UNREGISTRATION_DELAY() - 1);

        vm.startPrank(operator);
        vm.expectRevert(IRegistry.UnregistrationDelayNotMet.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_alreadyClaimed() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        vm.roll(block.number + registry.UNREGISTRATION_DELAY());

        vm.startPrank(operator);
        registry.claimCollateral(registrationRoot);

        // Try to claim again
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.NoCollateralToClaim.selector);
        registry.claimCollateral(registrationRoot);
    }
}

contract AddCollateralTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_addCollateral(uint56 addAmount) public {
        uint256 collateral = registry.MIN_COLLATERAL();
        vm.assume((addAmount + collateral) / 1 gwei < uint256(2 ** 56));

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        uint256 expectedCollateralGwei = (collateral + addAmount) / 1 gwei;
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectEmit(address(registry));
        emit IRegistry.CollateralAdded(registrationRoot, expectedCollateralGwei);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        OperatorData memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.collateralGwei, expectedCollateralGwei, "Collateral not added");
    }

    function test_addCollateral_overflow() public {
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        uint256 addAmount = 2 ** 56 * 1 gwei; // overflow uint56
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectRevert(IRegistry.CollateralOverflow.selector);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        OperatorData memory operatorData = getRegistrationData(registrationRoot);
        assertEq(operatorData.collateralGwei, uint56(collateral / 1 gwei), "Collateral should not be changed");
    }

    function test_addCollateral_notRegistered() public {
        bytes32 registrationRoot = bytes32(uint256(0));
        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.addCollateral{ value: 1 gwei }(registrationRoot);
    }
}

contract SlashRegistrationTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_slashRegistration_badSignature() public {
        uint256 collateral = 2 * registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        BLS.G1Point memory pubkey = BLS.toPublicKey(SECRET_KEY_1);

        // Use a different secret key to sign the registration
        BLS.G2Point memory signature = _registrationSignature(SECRET_KEY_2, operator);

        registrations[0] = IRegistry.Registration({ pubkey: pubkey, signature: signature });

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(
            registrationRoot, operator, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
        );

        // generate merkle proof
        bytes32[] memory leaves = _hashToLeaves(registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        uint256 operatorBalanceBefore = operator.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(challenger);
        uint256 rewardCollateralWei = registry.slashRegistration(
            registrationRoot,
            registrations[0],
            proof,
            0 // leafIndex
        );

        _verifySlashingBalances(
            operator,
            challenger,
            0,
            rewardCollateralWei,
            collateral,
            operatorBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );

        // ensure operator was deleted
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }

    function test_slashRegistrationHeight1_DifferentOwner() public {
        uint256 collateral = 2 * registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // thief tries to frontrun operator by setting his address as withdrawal address
        );

        _assertRegistration(
            registrationRoot,
            thief, // confirm thief's address is what was registered
            uint56(collateral / 1 gwei),
            uint32(block.number),
            type(uint32).max,
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
        _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);
    }

    function test_slashRegistrationHeight2_DifferentOwner() public {
        uint256 collateral = 2 * registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](2);
        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createRegistration(SECRET_KEY_2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // thief tries to frontrun operator by setting his address as withdrawal address
        );

        // Verify initial registration state
        _assertRegistration(
            registrationRoot, thief, uint56(collateral / 1 gwei), uint32(block.number), type(uint32).max, 0
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

    function test_slashRegistrationFuzz_DifferentOwner(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);
        uint256 collateral = registry.MIN_COLLATERAL();

        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createRegistration(SECRET_KEY_1 + i, operator);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // submit different withdrawal address than the one signed by validator keys
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
                operator, thief, 0, collateral, collateral, thiefBalanceBefore, operatorBalanceBefore, urcBalanceBefore
            );

            _assertRegistration(registrationRoot, address(0), 0, 0, 0, 0);

            // Re-register to reset the state
            registrationRoot = registry.register{ value: collateral }(
                registrations,
                thief // submit different withdrawal address than the one signed by validator keys
            );

            // update balances
            thiefBalanceBefore = thief.balance;
            operatorBalanceBefore = operator.balance;
            urcBalanceBefore = address(registry).balance;
        }
    }
}

contract RentrancyTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    // For setup we register() -> unregister() -> claimCollateral()
    // The registration's withdrawal address is the reentrant contract
    // Claiming collateral causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral()
    // The test succeeds because the reentract contract catches the errors
    function test_reentrantClaimCollateral() public {
        ReentrantRegistrationContract reentrantContract = new ReentrantRegistrationContract(address(registry));
        vm.deal(address(reentrantContract), 1000 ether);

        IRegistry.Registration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract));

        reentrantContract.register(registrations);

        // pretend to unregister
        reentrantContract.unregister();

        // wait for unregistration delay
        vm.roll(block.number + registry.UNREGISTRATION_DELAY());

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
        OperatorData memory operatorData = getRegistrationData(reentrantContract.registrationRoot());
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

        uint256 collateral = registry.MIN_COLLATERAL();
        IRegistry.Registration[] memory registrations = new IRegistry.Registration[](1);

        registrations[0] = _createRegistration(SECRET_KEY_1, operator);

        // frontrun to set withdrawal address to reentrantContract
        reentrantContract.register(registrations);

        _assertRegistration(
            reentrantContract.registrationRoot(),
            address(reentrantContract),
            uint56(reentrantContract.collateral() / 1 gwei),
            uint32(block.number),
            type(uint32).max,
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
