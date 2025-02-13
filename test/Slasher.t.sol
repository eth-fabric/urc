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

    function slash(
        ISlasher.Delegation calldata delegation,
        ISlasher.Commitment calldata commitment,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 slashAmountGwei) {
        slashAmountGwei = SLASH_AMOUNT_GWEI;
    }

    function slashFromOptIn(ISlasher.Commitment calldata commitment, bytes calldata evidence, address challenger)
        external
        returns (uint256 slashAmountGwei)
    {
        slashAmountGwei = SLASH_AMOUNT_GWEI;
    }
}

contract SlashCommitmentTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    function testDummySlasherUpdatesRegistry() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

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
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_GWEI()
        );

        uint256 gotSlashAmountGwei = registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            evidence
        );

        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");

        _verifySlashCommitmentBalances(
            challenger, gotSlashAmountGwei * 1 gwei, 0, challengerBalanceBefore, urcBalanceBefore
        );

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralGwei, collateral / 1 gwei - gotSlashAmountGwei, "collateralGwei not decremented"
        );

        // Verify the slashedBefore mapping is set
        bytes32 slashingDigest =
            keccak256(abi.encode(result.signedDelegation, signedCommitment, result.registrationRoot));

        assertEq(registry.slashedBefore(slashingDigest), true, "slashedBefore not set");
    }

    function testRevertFraudProofWindowNotMet() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

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
            signedCommitment,
            evidence
        );
    }

    function testRevertNotRegisteredProposer() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);
        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = bytes32(0);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[0].signature,
            invalidProof,
            0,
            result.signedDelegation,
            signedCommitment,
            ""
        );
    }

    function testRevertDelegationSignatureInvalid() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // Sign delegation with different secret key
        ISlasher.SignedDelegation memory badSignedDelegation =
            signDelegation(SECRET_KEY_2, result.signedDelegation.delegation);

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
            signedCommitment,
            ""
        );
    }

    function testRevertSlashAmountExceedsCollateral() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei - 1, // less than the slash amount
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);
        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

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
            signedCommitment,
            ""
        );
    }

    function testClaimAfterSlash() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);
        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

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
            signedCommitment,
            evidence
        );

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // attempt to claim collateral
        vm.expectRevert(IRegistry.SlashWindowNotMet.selector);
        vm.startPrank(operator);
        registry.claimSlashedCollateral(result.registrationRoot);

        // advance past the slash window
        vm.roll(operatorData.slashedAt + registry.SLASH_WINDOW() + 1);

        // attempt to slash with same evidence
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            evidence
        );

        // attempt to slash with different SignedCommitment
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
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
        _assertRegistration(result.registrationRoot, address(0), 0, 0, 0, 0);
    }

    // test multiple slashings
    function testMultipleSlashings() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);
        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

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
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_GWEI()
        );
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            evidence
        );

        // slash again with different SignedCommitment
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_GWEI()
        );
        registry.slashCommitment(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedCommitment,
            evidence
        );

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by 2 slashings
        assertEq(
            operatorData.collateralGwei,
            collateral / 1 gwei - 2 * dummySlasher.SLASH_AMOUNT_GWEI(),
            "collateralGwei not decremented"
        );
    }
}

contract SlashCommitmentFromOptInTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    function testDummySlasherUpdatesRegistry() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        // opt in to the slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;

        // slash
        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_GWEI()
        );

        uint256 gotSlashAmountGwei = registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");

        assertEq(dummySlasher.SLASH_AMOUNT_GWEI(), gotSlashAmountGwei, "Slash amount incorrect");

        _verifySlashCommitmentBalances(
            challenger, gotSlashAmountGwei * 1 gwei, 0, challengerBalanceBefore, urcBalanceBefore
        );

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralGwei, collateral / 1 gwei - gotSlashAmountGwei, "collateralGwei not decremented"
        );

        // Verify the SlasherCommitment mapping is cleared
        IRegistry.SlasherCommitment memory slasherCommitment =
            registry.getSlasherCommitment(result.registrationRoot, address(dummySlasher));

        assertEq(slasherCommitment.committer, address(0), "SlasherCommitment not cleared");
        assertEq(slasherCommitment.optedInAt, 0, "SlasherCommitment not cleared");
        assertEq(slasherCommitment.optedOutAt, 0, "SlasherCommitment not cleared");
    }

    function testRevertOperatorAlreadyUnregistered() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // skip past fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Unregister operator
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Wait for unregistration delay
        vm.roll(block.number + registry.UNREGISTRATION_DELAY() + 1);

        // Try to slash after unregistration delay
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.OperatorAlreadyUnregistered.selector);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");
    }

    function testRevertSlashWindowExpired() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // skip past fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // First slash
        vm.startPrank(challenger);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");

        // Wait for slash window to expire
        vm.roll(block.number + registry.SLASH_WINDOW() + 1);

        // Try to slash again after window expired
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");
    }

    function testRevertNotOptedIn() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Try to slash without opting in
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.NotOptedIn.selector);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");
    }

    function testRevertUnauthorizedCommitment() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create commitment signed by different key
        (address wrongCommitter, uint256 wrongCommitterKey) = makeAddrAndKey("wrongCommitter");
        ISlasher.SignedCommitment memory signedCommitment = basicCommitment(wrongCommitterKey, params.slasher, "");

        // skip past fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Try to slash with unauthorized commitment
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.UnauthorizedCommitment.selector);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");
    }

    function testRevertSlashAmountExceedsCollateral() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: dummySlasher.SLASH_AMOUNT_GWEI() * 1 gwei - 1, // Less than slash amount
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 0
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // skip past fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Try to slash with amount exceeding collateral
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashAmountExceedsCollateral.selector);
        registry.slashCommitmentFromOptIn(result.registrationRoot, signedCommitment, "");
    }
}

contract SlashEquivocationTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    function testEquivocation() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        // Sign delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        // submit both delegations
        uint256 challengerBalanceBefore = challenger.balance;
        vm.startPrank(challenger);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedDelegationTwo
        );

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by MIN_COLLATERAL
        assertEq(
            operatorData.collateralGwei,
            (collateral - registry.MIN_COLLATERAL()) / 1 gwei,
            "collateralGwei not decremented"
        );

        assertEq(
            challenger.balance, challengerBalanceBefore + registry.MIN_COLLATERAL(), "challenger did not receive reward"
        );
    }

    function testRevertEquivocationFraudProofWindowNotMet() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // Create second delegation with different metadata
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.FraudProofWindowNotMet.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );
    }

    function testRevertEquivocationNotRegisteredKey() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create invalid proof
        bytes32[] memory invalidProof = new bytes32[](1);
        invalidProof[0] = bytes32(0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.NotRegisteredKey.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            invalidProof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );
    }

    function testRevertEquivocationDelegationsAreSame() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.DelegationsAreSame.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            result.signedDelegation // Same delegation
        );
    }

    function testRevertEquivocationDifferentSlots() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: 1000
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // Create second delegation with different slot
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot + 1, // Different slot
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.DifferentSlots.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );
    }

    function testRevertEquivocationSlashingAlreadyOccurred() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        vm.startPrank(challenger);
        // First slash
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );

        // Try to slash again with same delegations
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );

        // Try reversing the order of the delegations
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            signedDelegationTwo,
            result.signedDelegation
        );
    }

    function testRevertEquivocationOperatorAlreadyUnregistered() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot,
            metadata: "different metadata"
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        // move past the fraud proof window
        vm.roll(block.number + registry.FRAUD_PROOF_WINDOW() + 1);

        // Unregister the operator
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Move past unregistration delay
        vm.roll(block.number + registry.UNREGISTRATION_DELAY() + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.OperatorAlreadyUnregistered.selector);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );
    }
}

contract SlashReentrantTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    // For setup we register() and delegate to the dummy slasher
    // The registration's withdrawal address is the reentrant contract
    // Triggering a slash causes the reentrant contract to reenter the registry and call: addCollateral(), unregister(), claimCollateral(), slashCommitment()
    // The test succeeds because the reentract contract catches the errors
    function testSlashEquivocationIsReentrantProtected() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: address(0),
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        (RegisterAndDelegateResult memory result, address reentrantContractAddress) =
            registerAndDelegateReentrant(params);
        ISlasher.SignedCommitment memory signedCommitment =
            basicCommitment(params.committerSecretKey, params.slasher, "");

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        bytes32[] memory proof = MerkleTree.generateProof(leaves, 0);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        uint256 challengerBalanceBefore = challenger.balance;
        uint256 urcBalanceBefore = address(registry).balance;
        uint56 operatorCollateralGweiBefore = getRegistrationData(result.registrationRoot).collateralGwei;

        // Sign a second delegation to equivocate
        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(
            params.proposerSecretKey,
            ISlasher.Delegation({
                proposer: BLS.toPublicKey(params.proposerSecretKey),
                delegate: BLS.toPublicKey(params.delegateSecretKey),
                committer: params.committer,
                slot: params.slot,
                metadata: "different metadata"
            })
        );

        // slash from a different address
        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            IRegistry.SlashingType.Equivocation,
            result.registrationRoot,
            reentrantContractAddress,
            challenger,
            address(registry),
            registry.MIN_COLLATERAL() / 1 gwei
        );
        uint256 gotSlashAmountGwei = registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[0].signature,
            proof,
            0,
            result.signedDelegation,
            signedDelegationTwo
        );
        assertEq(registry.MIN_COLLATERAL() / 1 gwei, gotSlashAmountGwei, "Slash amount incorrect");

        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by MIN_COLLATERAL
        assertEq(
            operatorData.collateralGwei,
            (IReentrantContract(reentrantContractAddress).collateral() - registry.MIN_COLLATERAL()) / 1 gwei,
            "collateralGwei not decremented"
        );

        assertEq(
            challenger.balance, challengerBalanceBefore + registry.MIN_COLLATERAL(), "challenger did not receive reward"
        );

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralGwei,
            operatorCollateralGweiBefore - gotSlashAmountGwei,
            "collateralGwei not decremented"
        );
    }
}

contract SlashConditionTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry();
        dummySlasher = new DummySlasher();
        vm.deal(operator, 100 ether);
        vm.deal(challenger, 100 ether);
        delegatePubKey = BLS.toPublicKey(SECRET_KEY_2);
        (committer, committerSecretKey) = makeAddrAndKey("commitmentsKey");
    }

    function test_cannot_unregister_after_slashing() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create two different delegations for the same slot to trigger equivocation
        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(
            params.proposerSecretKey,
            ISlasher.Delegation({
                proposer: BLS.toPublicKey(params.proposerSecretKey),
                delegate: BLS.toPublicKey(params.delegateSecretKey),
                committer: params.committer,
                slot: params.slot,
                metadata: "different metadata"
            })
        );

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        // Slash the operator for equivocation
        vm.startPrank(challenger);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedDelegationTwo
        );
        vm.stopPrank();

        // Verify operator was slashed
        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);
        assertEq(operatorData.slashedAt, block.number, "operator not slashed");

        // Try to unregister after being slashed
        vm.startPrank(operator);
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.unregister(result.registrationRoot);
    }

    function test_cannot_claimCollateral_after_slashing() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: collateral,
            owner: operator,
            delegateSecretKey: SECRET_KEY_2,
            committerSecretKey: committerSecretKey,
            committer: committer,
            slasher: address(dummySlasher),
            metadata: "",
            slot: uint64(UINT256_MAX)
        });

        RegisterAndDelegateResult memory result = registerAndDelegate(params);

        // Create two different delegations for the same slot to trigger equivocation
        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(
            params.proposerSecretKey,
            ISlasher.Delegation({
                proposer: BLS.toPublicKey(params.proposerSecretKey),
                delegate: BLS.toPublicKey(params.delegateSecretKey),
                committer: params.committer,
                slot: params.slot,
                metadata: "different metadata"
            })
        );

        // Setup proof
        bytes32[] memory leaves = _hashToLeaves(result.registrations);
        uint256 leafIndex = 0;
        bytes32[] memory proof = MerkleTree.generateProof(leaves, leafIndex);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.FRAUD_PROOF_WINDOW() + 1);

        // Start the normal unregistration path
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Slash the operator for equivocation
        vm.startPrank(challenger);
        registry.slashEquivocation(
            result.registrationRoot,
            result.registrations[leafIndex].signature,
            proof,
            leafIndex,
            result.signedDelegation,
            signedDelegationTwo
        );
        vm.stopPrank();

        // Verify operator was slashed
        OperatorData memory operatorData = getRegistrationData(result.registrationRoot);
        assertEq(operatorData.slashedAt, block.number, "operator not slashed");

        // Move past unregistration delay
        vm.roll(block.number + registry.UNREGISTRATION_DELAY() + 1);

        // Try to claim collateral through normal path - should fail
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.claimCollateral(result.registrationRoot);
    }
}
