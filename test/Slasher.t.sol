// SPDX-License-Identifier: MIT
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

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
    }

    function testDummySlasherUpdatesRegistry() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
        uint256 operatorBalanceBefore = operator.balance;
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

        _verifySlashingBalances(
            challenger,
            operator,
            dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei,
            dummySlasher.REWARD_AMOUNT_GWEI() * 1 gwei,
            collateral,
            challengerBalanceBefore,
            operatorBalanceBefore,
            urcBalanceBefore
        );

        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }

    function testRevertFraudProofWindowNotMet() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            withdrawalAddress: operator,
            delegateSecretKey: SECRET_KEY_2,
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
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
            slasher: address(dummySlasher),
            domainSeparator: dummySlasher.DOMAIN_SEPARATOR(),
            metadata: "",
            validUntil: uint64(UINT256_MAX)
        });

        (RegisterAndDelegateResult memory result, address reentrantContract) = registerAndDelegateReentrant(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 reentrantContractBalanceBefore = reentrantContract.balance;
        uint256 urcBalanceBefore = address(registry).balance;

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

        // verify balances updated correctly
        _verifySlashingBalances(
            challenger,
            address(reentrantContract),
            dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei,
            dummySlasher.REWARD_AMOUNT_GWEI() * 1 gwei,
            IReentrantContract(reentrantContract).collateral(),
            challengerBalanceBefore,
            reentrantContractBalanceBefore,
            urcBalanceBefore
        );

        // Verify operator was deleted
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }
}

// Helper contract that rejects ETH transfers
contract RejectEther {
    receive() external payable {
        revert("No ETH accepted");
    }
}
