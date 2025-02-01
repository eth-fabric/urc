// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import { BLS } from "../src/lib/BLS.sol";
import { MerkleTree } from "../src/lib/MerkleTree.sol";
import "../src/Registry.sol";
import { IRegistry } from "../src/IRegistry.sol";
import { ISlasher } from "../src/ISlasher.sol";
import { UnitTestHelper, IReentrantContract } from "./UnitTestHelper.sol";

contract DummySlasher is ISlasher {
    uint256 public SLASH_AMOUNT_GWEI = 1 ether / 1 gwei;
    uint256 public REWARD_AMOUNT_GWEI = 0.1 ether / 1 gwei; // MIN_COLLATERAL

    function DOMAIN_SEPARATOR() external view returns (bytes memory) {
        return bytes("DUMMY-SLASHER-DOMAIN-SEPARATOR");
    }

    function slash(ISlasher.Delegation calldata delegation, bytes calldata evidence, address challenger)
        external
        returns (uint256 slashAmountGwei, uint256 rewardAmountGwei)
    {
        slashAmountGwei = SLASH_AMOUNT_GWEI;
        rewardAmountGwei = REWARD_AMOUNT_GWEI;
    }
}

contract DummySlasherTest is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 commitmentSecretKey;
    address commitmentKey;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (commitmentKey, commitmentSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    function testDummySlasherUpdatesRegistry() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot,
            dummySlasher.SLASH_AMOUNT_GWEI(),
            dummySlasher.REWARD_AMOUNT_GWEI(),
            result.signedDelegation.delegation.proposerPubKey
        );

        (uint256 gotSlashAmountGwei, uint256 gotRewardAmountGwei) = registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );

        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");
        assertEq(dummySlasher.REWARD_AMOUNT_GWEI(), gotRewardAmountGwei, "Reward amount incorrect");

        _verifySlashCommitmentBalances(
            challenger,
            gotSlashAmountGwei * 1 gwei,
            gotRewardAmountGwei * 1 gwei,
            challengerBalanceBefore,
            urcBalanceBefore
        );

        IRegistry.Operator memory operatorData = getRegistrationData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralGwei,
            collateral / 1 gwei - gotSlashAmountGwei - gotRewardAmountGwei,
            "collateralGwei not decremented"
        );

        // Verify the slashedBefore mapping is set
        bytes32 slashingDigest = keccak256(abi.encode(result.signedDelegation, result.registrationRoot));
        assertEq(registry.slashedBefore(slashingDigest), true, "slashedBefore not set");
    }

    function testRevertFraudProofWindowNotMet() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // Try to slash before fraud proof window expires
        vm.expectRevert(IRegistry.FraudProofWindowNotMet.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );
    }

    function testRevertNotRegisteredProposer() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = bytes32(0);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.slashCommitment(
            result.registrationRoot, result.registrations[0].signature, invalidProof, 0, result.signedDelegation, ""
        );
    }

    function testRevertDelegationSignatureInvalid() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Sign delegation with different secret key
        ISlasher.SignedDelegation memory badSignedDelegation =
            signDelegation(SECRET_KEY_2, result.signedDelegation.delegation, params.domainSeparator);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.DelegationSignatureInvalid.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            badSignedDelegation,
            ""
        );
    }

    function testRevertSlashAmountExceedsCollateral() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei - 1, // less than the slash amount
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashAmountExceedsCollateral.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }

    function testRevertEthTransferFailed() public {
        // Deploy a contract that rejects ETH transfers
        RejectEther rejectEther = new RejectEther();

        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: address(rejectEther),
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.EthTransferFailed.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            ""
        );
    }

    function testClaimAfterSlash() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );

        IRegistry.Operator memory operatorData = getRegistrationData(result.registrationRoot);

        // attempt to claim collateral
        vm.expectRevert(IRegistry.SlashWindowNotMet.selector);
        vm.startPrank(operator);
        registry.claimSlashedCollateral(result.registrationRoot);

        // advance past the slash window
        console.log("operatorData.slashedAt", operatorData.slashedAt);
        vm.roll(operatorData.slashedAt + registry.SLASH_WINDOW() + 1);
        console.log("block.number", block.number);

        // attempt to slash with same evidence
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );

        // attempt to slash with different SignedDelegation
        result.signedDelegation.delegation.metadata = "different metadata";
        ISlasher.SignedDelegation memory differentSignedDelegation =
            signDelegation(SECRET_KEY_1, result.signedDelegation.delegation, dummySlasher.DOMAIN_SEPARATOR());
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            differentSignedDelegation,
            evidence
        );

        uint256 operatorCollateralBefore = operator.balance;

        // claim collateral
        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(result.registrationRoot, operatorData.collateralGwei);
        registry.claimSlashedCollateral(result.registrationRoot);

        // verify operator's balance is increased
        assertEq(
            operator.balance,
            operatorCollateralBefore + uint256(operatorData.collateralGwei) * 1 gwei,
            "operator did not claim collateral"
        );

        // verify operator was deleted
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0, 0);
    }

    // test multiple slashings
    function testMultipleSlashings() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot,
            dummySlasher.SLASH_AMOUNT_GWEI(),
            dummySlasher.REWARD_AMOUNT_GWEI(),
            result.signedDelegation.delegation.proposerPubKey
        );
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            evidence
        );

        // slash again with different SignedDelegation
        result.signedDelegation.delegation.metadata = "different metadata";
        ISlasher.SignedDelegation memory differentSignedDelegation =
            signDelegation(SECRET_KEY_1, result.signedDelegation.delegation, dummySlasher.DOMAIN_SEPARATOR());
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot,
            dummySlasher.SLASH_AMOUNT_GWEI(),
            dummySlasher.REWARD_AMOUNT_GWEI(),
            result.signedDelegation.delegation.proposerPubKey
        );
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            differentSignedDelegation,
            evidence
        );

        IRegistry.Operator memory operatorData = getRegistrationData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by 2 slashings
        assertEq(
            operatorData.collateralGwei,
            collateral / 1 gwei - 2 * (dummySlasher.SLASH_AMOUNT_GWEI() + dummySlasher.REWARD_AMOUNT_GWEI()),
            "collateralGwei not decremented"
        );
    }

    // For setup we register() and delegate to the dummy slasher
    // The registration's withdrawal address is the reentrant contract
    // Triggering a slash causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral(), slashCommitment()
    // The test succeeds because the reentract contract catches the errors
    function testSlashCommitmentIsReentrantProtected() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: address(0),
            delegateSecretKey: SECRET_KEY_2,
            commitmentSecretKey: commitmentSecretKey,
            commitmentKey: commitmentKey,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        (RegisterAndDelegateResult memory result,) = registerAndDelegateReentrant(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;
        uint56 operatorCollateralGweiBefore = getRegistrationData(result.registrationRoot).collateralGwei;

        // slash from a different address
        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            result.registrationRoot,
            dummySlasher.SLASH_AMOUNT_GWEI(),
            dummySlasher.REWARD_AMOUNT_GWEI(),
            result.signedDelegation.delegation.proposerPubKey
        );
        (uint256 gotSlashAmountGwei, uint256 gotRewardAmountGwei) = registry.slashCommitment(
            result.registrationRoot, result.registrations[0].signature, proof, 0, result.signedDelegation, evidence
        );
        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");
        assertEq(dummySlasher.REWARD_AMOUNT_GWEI(), gotRewardAmountGwei, "Reward amount incorrect");

        // verify balances updated correctly
        _verifySlashCommitmentBalances(
            challenger,
            gotSlashAmountGwei * 1 gwei,
            gotRewardAmountGwei * 1 gwei,
            challengerBalanceBefore,
            urcBalanceBefore
        );

        IRegistry.Operator memory operatorData = getRegistrationData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralGwei,
            operatorCollateralGweiBefore - gotSlashAmountGwei - gotRewardAmountGwei,
            "collateralGwei not decremented"
        );
    }
}

// Helper contract that rejects ETH transfers
contract RejectEther {
    receive() external payable {
        revert("No ETH accepted");
    }
}
