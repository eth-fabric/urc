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
    uint256 public SLASH_AMOUNT_WEI = 1 ether;

    function slash(
        ISlasher.Delegation calldata delegation,
        ISlasher.Commitment calldata commitment,
        address committer,
        bytes calldata evidence,
        address challenger
    ) external returns (uint256 slashAmountWei) {
        slashAmountWei = SLASH_AMOUNT_WEI;
    }
}

contract SlashCommitmentTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry(defaultConfig());
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
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

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
            dummySlasher.SLASH_AMOUNT_WEI()
        );

        uint256 gotSlashAmountWei = registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        assertEq(dummySlasher.SLASH_AMOUNT_WEI(), gotSlashAmountWei, "Slash amount incorrect");

        _verifySlashCommitmentBalances(challenger, gotSlashAmountWei, 0, challengerBalanceBefore, urcBalanceBefore);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(operatorData.collateralWei, collateral - gotSlashAmountWei, "collateralGwei not decremented");

        // Verify the slashedBefore mapping is set
        bytes32 slashingDigest =
            keccak256(abi.encode(result.signedDelegation, signedCommitment, result.registrationRoot));

        assertEq(registry.slashingEvidenceAlreadyUsed(slashingDigest), true, "slashedBefore not set");
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);
        bytes memory evidence = "";

        // Try to slash before fraud proof window expires
        vm.expectRevert(IRegistry.FraudProofWindowNotMet.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);
    }

    function testRevertInvalidProof() public {
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

        // Create invalid proof,
        IRegistry.RegistrationProof memory proof = IRegistry.RegistrationProof({
            registrationRoot: result.registrationRoot,
            registration: result.registrations[0],
            merkleProof: new bytes32[](1),
            leafIndex: 0
        });

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.expectRevert(IRegistry.InvalidProof.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, "");
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.expectRevert(IRegistry.DelegationSignatureInvalid.selector);
        registry.slashCommitment(proof, badSignedDelegation, signedCommitment, "");
    }

    function testRevertSlashAmountExceedsCollateral() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: dummySlasher.SLASH_AMOUNT_WEI() - 1, // less than the slash amount
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashAmountExceedsCollateral.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, "");
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
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // attempt to claim collateral
        vm.expectRevert(IRegistry.SlashWindowNotMet.selector);
        vm.startPrank(operator);
        registry.claimSlashedCollateral(result.registrationRoot);

        // advance past the slash window
        vm.roll(operatorData.slashedAt + registry.getConfig().slashWindow + 1);

        // attempt to slash with same evidence
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        // attempt to slash with different SignedCommitment
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        uint256 operatorCollateralBefore = operator.balance;

        // claim collateral
        vm.startPrank(operator);
        vm.expectEmit(address(registry));
        emit IRegistry.CollateralClaimed(result.registrationRoot, operatorData.collateralWei);
        registry.claimSlashedCollateral(result.registrationRoot);

        // verify operator's balance is increased
        assertEq(
            operator.balance, operatorCollateralBefore + operatorData.collateralWei, "operator did not claim collateral"
        );

        // verify operator was deleted
        assertEq(registry.getOperatorData(result.registrationRoot).deleted, true, "operator was not deleted");
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
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);
        bytes memory evidence = "";

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_WEI()
        );
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        // slash again with different SignedCommitment
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectEmit(address(registry));
        emit IRegistry.OperatorSlashed(
            IRegistry.SlashingType.Commitment,
            result.registrationRoot,
            operator,
            challenger,
            address(dummySlasher),
            dummySlasher.SLASH_AMOUNT_WEI()
        );
        registry.slashCommitment(proof, result.signedDelegation, signedCommitment, evidence);

        // verify operator's collateralGwei is decremented by 2 slashings
        assertEq(
            registry.getOperatorData(result.registrationRoot).collateralWei,
            collateral - 2 * dummySlasher.SLASH_AMOUNT_WEI(),
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
        registry = new Registry(defaultConfig());
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
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

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
            dummySlasher.SLASH_AMOUNT_WEI()
        );

        uint256 gotSlashAmountWei = registry.slashCommitment(result.registrationRoot, signedCommitment, "");

        assertEq(dummySlasher.SLASH_AMOUNT_WEI(), gotSlashAmountWei, "Slash amount incorrect");

        _verifySlashCommitmentBalances(challenger, gotSlashAmountWei, 0, challengerBalanceBefore, urcBalanceBefore);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's collateralGwei is decremented
        assertEq(operatorData.collateralWei, collateral - gotSlashAmountWei, "collateralWei not decremented");

        // Verify the SlasherCommitment was set to slashed
        IRegistry.SlasherCommitment memory slasherCommitment =
            registry.getSlasherCommitment(result.registrationRoot, address(dummySlasher));

        assertEq(slasherCommitment.slashed, true, "SlasherCommitment not slashed");
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
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Unregister operator
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Wait for unregistration delay
        vm.roll(block.number + registry.getConfig().unregistrationDelay + 1);

        // Try to slash after unregistration delay
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.OperatorAlreadyUnregistered.selector);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");
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
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // First slash
        vm.startPrank(challenger);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");

        // Wait for slash window to expire
        vm.roll(block.number + registry.getConfig().slashWindow + 1);

        // Try to slash again after window expired
        signedCommitment = basicCommitment(params.committerSecretKey, params.slasher, "different payload");
        vm.expectRevert(IRegistry.SlashWindowExpired.selector);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");
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
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Try to slash without opting in
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.NotOptedIn.selector);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");
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
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Try to slash with unauthorized commitment
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.UnauthorizedCommitment.selector);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");
    }

    function testRevertSlashAmountExceedsCollateral() public {
        RegisterAndDelegateParams memory params = RegisterAndDelegateParams({
            proposerSecretKey: SECRET_KEY_1,
            collateral: dummySlasher.SLASH_AMOUNT_WEI() - 1, // Less than slash amount
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
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Opt in to slasher
        vm.startPrank(operator);
        registry.optInToSlasher(result.registrationRoot, address(dummySlasher), committer);

        // Wait for fraud proof window
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Try to slash with amount exceeding collateral
        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.SlashAmountExceedsCollateral.selector);
        registry.slashCommitment(result.registrationRoot, signedCommitment, "");
    }
}

contract SlashEquivocationTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry(defaultConfig());
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
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        // Sign delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(0), // different delegate
            committer: params.committer,
            slot: params.slot,
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        // submit both delegations
        uint256 challengerBalanceBefore = challenger.balance;
        vm.startPrank(challenger);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by MIN_COLLATERAL
        assertEq(
            operatorData.collateralWei,
            (collateral - registry.getConfig().minCollateralWei),
            "collateralWei not decremented"
        );

        assertEq(
            challenger.balance,
            challengerBalanceBefore + registry.getConfig().minCollateralWei / 2,
            "challenger did not receive reward"
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(0), // different delegate
            committer: params.committer,
            slot: params.slot,
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.FraudProofWindowNotMet.selector);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
    }

    function testRevertEquivocationInvalidProof() public {
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

        // Create invalid proof,
        IRegistry.RegistrationProof memory proof = IRegistry.RegistrationProof({
            registrationRoot: result.registrationRoot,
            registration: result.registrations[0],
            merkleProof: new bytes32[](1),
            leafIndex: 0
        });

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(0), // different delegate
            committer: params.committer,
            slot: params.slot,
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.InvalidProof.selector);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.DelegationsAreSame.selector);
        registry.slashEquivocation(
            proof,
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // Create second delegation with different slot
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(params.delegateSecretKey),
            committer: params.committer,
            slot: params.slot + 1, // Different slot
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.DifferentSlots.selector);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(0), // different delegate
            committer: params.committer,
            slot: params.slot,
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        vm.startPrank(challenger);
        // First slash
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);

        // Try to slash again with same delegations
        vm.expectRevert(IRegistry.OperatorAlreadyEquivocated.selector);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);

        // Try reversing the order of the delegations
        vm.expectRevert(IRegistry.OperatorAlreadyEquivocated.selector);
        registry.slashEquivocation(proof, signedDelegationTwo, result.signedDelegation);
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

        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // Create second delegation
        ISlasher.Delegation memory delegationTwo = ISlasher.Delegation({
            proposer: BLS.toPublicKey(params.proposerSecretKey),
            delegate: BLS.toPublicKey(0), // different delegate
            committer: params.committer,
            slot: params.slot,
            metadata: ""
        });

        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(params.proposerSecretKey, delegationTwo);

        // move past the fraud proof window
        vm.roll(block.number + registry.getConfig().fraudProofWindow + 1);

        // Unregister the operator
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Move past unregistration delay
        vm.roll(block.number + registry.getConfig().unregistrationDelay + 1);

        vm.startPrank(challenger);
        vm.expectRevert(IRegistry.OperatorAlreadyUnregistered.selector);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
    }
}

contract SlashReentrantTester is UnitTestHelper {
    DummySlasher dummySlasher;
    BLS.G1Point delegatePubKey;
    uint256 collateral = 100 ether;
    uint256 committerSecretKey;
    address committer;

    function setUp() public {
        registry = new Registry(defaultConfig());
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

        // Setup proof
        IRegistry.RegistrationProof memory proof =
            registry.getRegistrationProof(result.registrations, reentrantContractAddress, 0);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        uint256 challengerBalanceBefore = challenger.balance;
        uint80 operatorCollateralWeiBefore = registry.getOperatorData(result.registrationRoot).collateralWei;

        // Sign a second delegation to equivocate
        ISlasher.SignedDelegation memory signedDelegationTwo = signDelegation(
            params.proposerSecretKey,
            ISlasher.Delegation({
                proposer: BLS.toPublicKey(params.proposerSecretKey),
                delegate: BLS.toPublicKey(0), // different delegate
                committer: params.committer,
                slot: params.slot,
                metadata: ""
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
            registry.getConfig().minCollateralWei
        );
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);

        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);

        // verify operator's collateralGwei is decremented by MIN_COLLATERAL
        assertEq(
            operatorData.collateralWei,
            (IReentrantContract(reentrantContractAddress).collateral() - registry.getConfig().minCollateralWei),
            "collateralWei not decremented"
        );

        assertEq(
            challenger.balance,
            challengerBalanceBefore + registry.getConfig().minCollateralWei / 2,
            "challenger did not receive reward"
        );

        // Verify operator's slashedAt is set
        assertEq(operatorData.slashedAt, block.number, "slashedAt not set");

        // Verify operator's equivocated is set
        assertEq(operatorData.equivocated, true, "operator not equivocated");

        // Verify operator's collateralGwei is decremented
        assertEq(
            operatorData.collateralWei,
            operatorCollateralWeiBefore - registry.getConfig().minCollateralWei,
            "collateralWei not decremented"
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
        registry = new Registry(defaultConfig());
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
                delegate: BLS.toPublicKey(0), // different delegate
                committer: params.committer,
                slot: params.slot,
                metadata: ""
            })
        );

        // Setup proof
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        // Slash the operator for equivocation
        vm.startPrank(challenger);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
        vm.stopPrank();

        // Verify operator was slashed
        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);
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
                delegate: BLS.toPublicKey(0), // different delegate
                committer: params.committer,
                slot: params.slot,
                metadata: ""
            })
        );

        // Setup proof
        IRegistry.RegistrationProof memory proof = registry.getRegistrationProof(result.registrations, operator, 0);

        // skip past fraud proof window
        vm.roll(block.timestamp + registry.getConfig().fraudProofWindow + 1);

        // Start the normal unregistration path
        vm.startPrank(operator);
        registry.unregister(result.registrationRoot);

        // Slash the operator for equivocation
        vm.startPrank(challenger);
        registry.slashEquivocation(proof, result.signedDelegation, signedDelegationTwo);
        vm.stopPrank();

        // Verify operator was slashed
        IRegistry.OperatorData memory operatorData = registry.getOperatorData(result.registrationRoot);
        assertEq(operatorData.slashedAt, block.number, "operator not slashed");
        assertEq(operatorData.equivocated, true, "operator not equivocated");

        // Move past unregistration delay
        vm.roll(block.number + registry.getConfig().unregistrationDelay + 1);

        // Try to claim collateral through normal path - should fail
        vm.expectRevert(IRegistry.SlashingAlreadyOccurred.selector);
        registry.claimCollateral(result.registrationRoot);
    }
}
