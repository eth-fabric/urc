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
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_register() public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        basicRegistration(SECRET_KEY_1, collateral, operator);
    }

    function test_register_insufficientCollateral() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        vm.expectRevert(IRegistry.InsufficientCollateral.selector);
        registry.register{ value: collateral - 1 }(registrations, operator);
    }

    function test_register_OperatorAlreadyRegistered() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(registrationRoot, operator, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        // Attempt duplicate registration
        vm.expectRevert(IRegistry.OperatorAlreadyRegistered.selector);
        registry.register{ value: collateral }(registrations, operator);
    }

    function test_verifyMerkleProofHeight1() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(registrationRoot, operator, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, operator, 0);

        // reverts if proof is invalid
        registry.verifyMerkleProof(proof);
    }

    function test_verifyMerkleProofHeight2() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](2);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createSignedRegistration(SECRET_KEY_2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(registrationRoot, operator, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        // Test first proof path - leafIndex = 0
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, operator, 0);
        registry.verifyMerkleProof(proof);

        // Test second proof path - leafIndex = 1
        proof = registry.getRegistrationProof(registrations, operator, 1);
        registry.verifyMerkleProof(proof);
    }

    function test_verifyMerkleProofHeight3() public {
        uint256 collateral = 3 * registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](3); // will be padded to 4

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createSignedRegistration(SECRET_KEY_1 + 1, operator);

        registrations[2] = _createSignedRegistration(SECRET_KEY_1 + 2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(registrationRoot, operator, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        // Test all proof paths
        for (uint256 i = 0; i < registrations.length; i++) {
            IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, operator, i);
            registry.verifyMerkleProof(proof);
        }
    }

    function test_fuzzRegister(uint8 n) public {
        vm.assume(n > 0);
        uint256 size = uint256(n);

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createSignedRegistration(SECRET_KEY_1 + i, operator);
        }

        // Register the keys
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);

        // Test all proof paths
        for (uint256 i = 0; i < registrations.length; i++) {
            IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, operator, i);
            registry.verifyMerkleProof(proof);
        }
    }
}

contract UnregisterTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_unregister() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorUnregistered(registrationRoot);
        registry.unregister(registrationRoot);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(registrationRoot);
        assertEq(operatorData.unregisteredAt, uint48(block.number), "Wrong unregistration block");
        assertEq(operatorData.registeredAt, uint48(block.number), "Wrong registration block"); // Should remain unchanged
    }

    function test_unregister_wrongOperator() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        // thief tries to unregister operator's registration
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.unregister(registrationRoot);
    }

    function test_unregister_alreadyUnregistered() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

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
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_optInAndOut() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address committer = address(1234);
        address slasher = address(5678);

        // Wait for opt-in delay
        vm.warp(block.timestamp + registry.getConfig().fraudProofWindow);

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorOptedIn(registrationRoot, slasher, committer);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Wait for opt-in delay
        vm.warp(block.timestamp + registry.getConfig().optInDelay);

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorOptedOut(registrationRoot, slasher);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }

    function test_optInToSlasher_wrongOperator() public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.warp(block.timestamp + registry.getConfig().fraudProofWindow);

        // Try to opt in from wrong address
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.optInToSlasher(registrationRoot, slasher, committer);
    }

    function test_optInToSlasher_alreadyOptedIn() public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.warp(block.timestamp + registry.getConfig().fraudProofWindow);

        // First opt-in
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt in again
        vm.expectRevert(IRegistry.AlreadyOptedIn.selector);
        registry.optInToSlasher(registrationRoot, slasher, committer);
    }

    function test_optOutOfSlasher_wrongOperator() public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.warp(block.timestamp + registry.getConfig().fraudProofWindow);

        // Opt in first
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt out from wrong address
        vm.startPrank(thief);
        vm.expectRevert(IRegistry.WrongOperator.selector);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }

    function test_optOutOfSlasher_optInDelayNotMet() public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);
        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        address slasher = address(1234);
        address committer = address(5678);

        // Wait for fraud proof window
        vm.warp(block.timestamp + registry.getConfig().fraudProofWindow);

        // Opt in
        vm.startPrank(operator);
        registry.optInToSlasher(registrationRoot, slasher, committer);

        // Try to opt out before delay
        vm.warp(block.timestamp + registry.getConfig().optInDelay - 1);
        vm.expectRevert(IRegistry.OptInDelayNotMet.selector);
        registry.optOutOfSlasher(registrationRoot, slasher);
    }
}

contract ClaimCollateralTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_claimCollateral() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Wait for unregistration delay
        vm.warp(block.timestamp + registry.getConfig().unregistrationDelay);

        uint256 balanceBefore = operator.balance;

        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(registrationRoot, uint256(collateral));
        registry.claimCollateral(registrationRoot);

        assertEq(operator.balance, balanceBefore + collateral, "Collateral not returned");

        // Verify registration was deleted
        assertEq(registry.getOperatorData(registrationRoot).deleted, true, "Registration not deleted");
    }

    function test_claimCollateral_notUnregistered() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        // Try to claim without unregistering first
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.NotUnregistered.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_delayNotMet() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        // Try to claim before delay has passed
        vm.warp(block.timestamp + registry.getConfig().unregistrationDelay - 1);

        vm.startPrank(operator);
        vm.expectRevert(IRegistry.UnregistrationDelayNotMet.selector);
        registry.claimCollateral(registrationRoot);
    }

    function test_claimCollateral_alreadyClaimed() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        vm.startPrank(operator);
        registry.unregister(registrationRoot);

        vm.warp(block.timestamp + registry.getConfig().unregistrationDelay);

        vm.startPrank(operator);
        registry.claimCollateral(registrationRoot);

        // Try to claim again
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.OperatorDeleted.selector);
        registry.claimCollateral(registrationRoot);
    }
}

contract AddCollateralTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_addCollateral(uint56 addAmount) public {
        uint256 collateral = registry.getConfig().minCollateralWei;
        vm.assume((addAmount + collateral) < uint256(2 ** 80));

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        uint256 expectedCollateralWei = collateral + addAmount;
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectEmit(address(registry));
        emit IRegistry.CollateralAdded(registrationRoot, expectedCollateralWei);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        assertEq(
            registry.getOperatorData(registrationRoot).collateralWei, expectedCollateralWei, "Collateral not added"
        );
    }

    function test_addCollateral_overflow() public {
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = _setupSingleRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        uint256 addAmount = 2 ** 80; // overflow uint80
        vm.deal(operator, addAmount);
        vm.startPrank(operator);

        vm.expectRevert(IRegistry.CollateralOverflow.selector);
        registry.addCollateral{ value: addAmount }(registrationRoot);

        assertEq(
            registry.getOperatorData(registrationRoot).collateralWei,
            uint80(collateral),
            "Collateral should not be changed"
        );
    }

    function test_addCollateral_noCollateral() public {
        bytes32 registrationRoot = bytes32(uint256(0));
        vm.expectRevert(IRegistry.NoCollateral.selector);
        registry.addCollateral{ value: 1 gwei }(registrationRoot);
    }
}

contract SlashRegistrationTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        vm.deal(thief, 100 ether);
    }

    function test_slashRegistration_badSignature() public {
        uint256 collateral = 2 * registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        BLS.G1Point memory pubkey = BLS.toPublicKey(SECRET_KEY_1);

        // Use a different secret key to sign the registration
        BLS.G2Point memory signature = _registrationSignature(SECRET_KEY_2, operator);

        registrations[0] = IRegistry.SignedRegistration({ pubkey: pubkey, signature: signature });

        bytes32 registrationRoot = registry.register{ value: collateral }(registrations, operator);

        _assertRegistration(registrationRoot, operator, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        uint256 operatorBalanceBefore = operator.balance;
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(challenger);
        registry.slashRegistration(registry.getRegistrationProof(registrations, operator, 0));

        vm.warp(block.timestamp + registry.getConfig().slashWindow);
        vm.startPrank(operator);
        registry.claimSlashedCollateral(registrationRoot);

        _verifySlashingBalances(
            challenger,
            operator,
            registry.getConfig().minCollateralWei / 2,
            registry.getConfig().minCollateralWei / 2,
            collateral,
            challengerBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );

        // ensure operator was deleted
        assertEq(registry.getOperatorData(registrationRoot).deleted, true, "operator was not deleted");
    }

    function test_slashRegistrationHeight1_DifferentOwner() public {
        uint256 collateral = 2 * registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // thief tries to frontrun operator by setting his address as withdrawal address
        );

        _assertRegistration(
            registrationRoot,
            thief, // confirm thief's address is what was registered
            uint80(collateral),
            uint48(block.number),
            type(uint48).max,
            0
        );

        uint256 thiefBalanceBefore = thief.balance;
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Note that proof is created using the thief's address as the owner
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, thief, 0);

        vm.startPrank(challenger);
        registry.slashRegistration(proof);

        vm.warp(block.timestamp + registry.getConfig().slashWindow);
        vm.startPrank(thief);
        registry.claimSlashedCollateral(registrationRoot);

        _verifySlashingBalances(
            challenger,
            thief,
            registry.getConfig().minCollateralWei / 2,
            registry.getConfig().minCollateralWei / 2,
            collateral,
            challengerBalanceBefore,
            thiefBalanceBefore,
            urcBalanceBefore
        );

        // ensure operator was deleted
        assertEq(registry.getOperatorData(registrationRoot).deleted, true, "operator was not deleted");
    }

    function test_slashRegistrationHeight2_DifferentOwner() public {
        uint256 collateral = 2 * registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](2);
        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        registrations[1] = _createSignedRegistration(SECRET_KEY_2, operator);

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // thief tries to frontrun operator by setting his address as withdrawal address
        );

        // Verify initial registration state
        _assertRegistration(registrationRoot, thief, uint80(collateral), uint48(block.number), type(uint48).max, 0);

        uint256 thiefBalanceBefore = thief.balance;
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Note that proof is created using the thief's address as the owner
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, thief, 0);

        vm.startPrank(challenger);
        registry.slashRegistration(proof);

        vm.warp(block.timestamp + registry.getConfig().slashWindow);
        vm.startPrank(thief);
        registry.claimSlashedCollateral(registrationRoot);

        _verifySlashingBalances(
            challenger,
            thief,
            registry.getConfig().minCollateralWei / 2,
            registry.getConfig().minCollateralWei / 2,
            collateral,
            challengerBalanceBefore,
            thiefBalanceBefore,
            urcBalanceBefore
        );
    }

    function test_slashRegistrationFuzz_DifferentOwner(uint8 n, uint8 leafIndex) public {
        vm.assume(n > 0);
        vm.assume(leafIndex < n);
        uint256 size = uint256(n);
        uint256 collateral = registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](size);
        for (uint256 i = 0; i < size; i++) {
            registrations[i] = _createSignedRegistration(SECRET_KEY_1 + i, operator);
        }

        bytes32 registrationRoot = registry.register{ value: collateral }(
            registrations,
            thief // submit different withdrawal address than the one signed by validator keys
        );

        uint256 thiefBalanceBefore = thief.balance;
        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // Note that proof is created using the thief's address as the owner
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, thief, leafIndex);

        vm.startPrank(challenger);
        registry.slashRegistration(proof);

        vm.warp(block.timestamp + registry.getConfig().slashWindow);
        vm.startPrank(thief);
        registry.claimSlashedCollateral(registrationRoot);

        _verifySlashingBalances(
            challenger,
            thief,
            registry.getConfig().minCollateralWei / 2,
            registry.getConfig().minCollateralWei / 2,
            collateral,
            challengerBalanceBefore,
            thiefBalanceBefore,
            urcBalanceBefore
        );

        assertEq(registry.getOperatorData(registrationRoot).deleted, true, "operator was not deleted");
    }

    function test_slashRegistration_SlashingAlreadyOccurred() public {
        uint256 collateral = 2 * registry.getConfig().minCollateralWei;

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        BLS.G1Point memory pubkey = BLS.toPublicKey(SECRET_KEY_1);

        // Use a different secret key to sign the registration
        BLS.G2Point memory signature = _registrationSignature(SECRET_KEY_2, operator);

        registrations[0] = IRegistry.SignedRegistration({ pubkey: pubkey, signature: signature });

        registry.register{ value: collateral }(registrations, operator);

        // Get the proof
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(registrations, operator, 0);

        vm.startPrank(challenger);
        registry.slashRegistration(proof);

        // Try to slash again with same proof
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.slashRegistration(proof);
    }
}

contract RentrancyTester is UnitTestHelper {
    using BLS for *;

    function setUp() public {
        registry = new Registry(defaultConfig());
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

        IRegistry.SignedRegistration[] memory registrations =
            _setupSingleRegistration(SECRET_KEY_1, address(reentrantContract));

        reentrantContract.register(registrations);

        // pretend to unregister
        reentrantContract.unregister();

        // wait for unregistration delay
        vm.warp(block.timestamp + registry.getConfig().unregistrationDelay);

        uint256 balanceBefore = address(reentrantContract).balance;

        vm.prank(address(reentrantContract));
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(reentrantContract.registrationRoot(), reentrantContract.collateral());

        // initiate reentrancy
        reentrantContract.claimCollateral();

        assertEq(
            address(reentrantContract).balance,
            balanceBefore + reentrantContract.collateral(),
            "Collateral not returned"
        );

        // Verify registration was deleted
        assertEq(
            registry.getOperatorData(reentrantContract.registrationRoot()).deleted, true, "operator was not deleted"
        );
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

        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](1);

        registrations[0] = _createSignedRegistration(SECRET_KEY_1, operator);

        // frontrun to set withdrawal address to reentrantContract
        reentrantContract.register(registrations);

        _assertRegistration(
            reentrantContract.registrationRoot(),
            address(reentrantContract),
            uint80(reentrantContract.collateral()),
            uint48(block.number),
            type(uint48).max,
            0
        );

        IRegistry.RegistrationProof memory proof =
            registry.getRegistrationProof(registrations, address(reentrantContract), 0);

        // operator can slash the registration
        vm.startPrank(operator);
        registry.slashRegistration(proof);
    }
}

contract RegisterGasTest is UnitTestHelper {
    function setUp() public {
        registry = new Registry(defaultConfig());
        vm.deal(operator, 100 ether);
    }

    function registrations(uint256 n) internal returns (IRegistry.SignedRegistration[] memory) {
        IRegistry.SignedRegistration[] memory registrations = new IRegistry.SignedRegistration[](n);
        for (uint256 i = 0; i < n; i++) {
            registrations[i] = _createSignedRegistration(SECRET_KEY_1 + i, operator);
        }
        return registrations;
    }

    function test_gas_register_1() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(1);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_2() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(2);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_4() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(4);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_8() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(8);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_16() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(16);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_32() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(32);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_64() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(64);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_128() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(128);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_256() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(256);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_512() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(512);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }

    function test_gas_register_1024() public {
        IRegistry.SignedRegistration[] memory registrations = registrations(1024);
        vm.resetGasMetering();
        vm.startPrank(operator);
        registry.register{ value: registry.getConfig().minCollateralWei }(registrations, operator);
    }
}