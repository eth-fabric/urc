// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import {Test} from "forge-std/Test.sol";
import {BLSUtils} from "../src/lib/BLS2.sol";
import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract BLSTest2 is Test {
    /// @dev Demonstrates the signing and verification of a message.
    function testSignAndVerify(
        uint256 privateKey,
        bytes memory message,
        bytes memory domainSeparator
    ) public view {
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(privateKey);
        BLS.G2Point memory signature = BLSUtils.sign(
            message,
            privateKey,
            domainSeparator
        );
        assert(BLSUtils.verify(message, signature, publicKey, domainSeparator));
    }

    /// @dev Demonstrates the aggregation and verification of two signatures.
    function testAggregation(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes memory message,
        bytes memory domainSeparator
    ) public view {
        // public keys
        BLS.G1Point memory pk1 = BLSUtils.toPublicKey(privateKey1);
        BLS.G1Point memory pk2 = BLSUtils.toPublicKey(privateKey2);

        // signatures
        BLS.G2Point memory sig1 = BLSUtils.sign(
            message,
            privateKey1,
            domainSeparator
        );
        BLS.G2Point memory sig2 = BLSUtils.sign(
            message,
            privateKey2,
            domainSeparator
        );

        // aggregated signature
        BLS.G2Point memory sig = BLS.add(sig1, sig2);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        g1Points[0] = BLSUtils.NEGATED_G1_GENERATOR();
        g1Points[1] = pk1;
        g1Points[2] = pk2;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);
        g2Points[0] = sig;
        g2Points[1] = BLSUtils.toMessagePoint(message, domainSeparator);
        g2Points[2] = BLSUtils.toMessagePoint(message, domainSeparator);

        assert(BLS.pairing(g1Points, g2Points));
    }

    function testToMessagePoint(
        bytes memory message,
        bytes memory domainSeparator
    ) public view {
        BLS.G2Point memory messagePoint = BLSUtils.toMessagePoint(
            message,
            domainSeparator
        );
        BLS.G2Point memory messagePointExpected = BLS.toG2(
            BLS.Fp2({
                c0_a: 0,
                c0_b: 0,
                c1_a: 0,
                c1_b: keccak256(abi.encodePacked(domainSeparator, message))
            })
        );

        assert(
            messagePoint.x_c0_a == messagePointExpected.x_c0_a &&
                messagePoint.x_c0_b == messagePointExpected.x_c0_b &&
                messagePoint.x_c1_a == messagePointExpected.x_c1_a &&
                messagePoint.x_c1_b == messagePointExpected.x_c1_b &&
                messagePoint.y_c0_a == messagePointExpected.y_c0_a &&
                messagePoint.y_c0_b == messagePointExpected.y_c0_b &&
                messagePoint.y_c1_a == messagePointExpected.y_c1_a &&
                messagePoint.y_c1_b == messagePointExpected.y_c1_b
        );
    }

    function testToPublicKey() public view {
        uint256 privateKey = 12356;

        // uncompressed public key
        BLS.G1Point memory expected = BLS.G1Point(
            BLSUtils._u(12115118667309283734868789696201968385),
            BLSUtils._u(
                102796267992108309135721548586500937750960769774310798537421982072779087272819
            ),
            BLSUtils._u(15699442850880472822588013448545136667),
            BLSUtils._u(
                697141831937854224682724016220779412457574525815594559914325383387627997986
            )
        );

        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(privateKey);
        assert(
            publicKey.x_a == expected.x_a &&
                publicKey.x_b == expected.x_b &&
                publicKey.y_a == expected.y_a &&
                publicKey.y_b == expected.y_b
        );
    }

    function testG1PointCompress_1() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(123456);
        BLS.Fp memory result = BLSUtils.compress(point);

        // Expected result: 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        assert(
            result.a == BLSUtils._u(233189109563333818632959426218981028728)
        );
        assert(
            result.b ==
                BLSUtils._u(
                    38732273024956312936195524807674957651409788979825024437260187772136397129126
                )
        );
    }

    function testG1PointCompress_2() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(69420);
        BLS.Fp memory result = BLSUtils.compress(point);

        // Expected result: 0xb9e16ee4c0c0f6fd65b48c8dc759038bd2eebd979e489d08d69825bed32a37c3cc69e9e05f577445ee27319791832961
        assert(
            result.a == BLSUtils._u(247077695202111629659213208963742499723)
        );
        assert(
            result.b ==
                BLSUtils._u(
                    95407516321583900695556749922087294361570042875752728076201341488189472450913
                )
        );
    }
}

contract BLSGasTest2 is Test {
    function testG1AddGas() public {
        BLS.G1Point memory a = BLSUtils.toPublicKey(1234);
        BLS.G1Point memory b = BLSUtils.toPublicKey(5678);
        vm.resetGasMetering();
        BLS.add(a, b);
    }

    function testG1MulGas() public {
        BLS.G1Point memory a = BLSUtils.toPublicKey(1234);
        vm.resetGasMetering();
        BLSUtils.mul(a, BLSUtils._u(1234));
    }

    function testG1MSMGas() public {
        BLS.G1Point[] memory points = new BLS.G1Point[](2);
        points[0] = BLSUtils.toPublicKey(1234);
        points[1] = BLSUtils.toPublicKey(5678);
        bytes32[] memory scalars = new bytes32[](2);
        scalars[0] = BLSUtils._u(1234);
        scalars[1] = BLSUtils._u(5678);
        vm.resetGasMetering();
        BLS.msm(points, scalars);
    }

    function testG2AddGas() public {
        BLS.G2Point memory g2A = BLSUtils.sign("hello", 1234, "");

        BLS.G2Point memory g2B = BLSUtils.sign("world", 5678, "");
        vm.resetGasMetering();
        BLS.add(g2A, g2B);
    }

    function testG2MulGas() public {
        BLS.G2Point memory g2A = BLSUtils.sign("hello", 1234, "");
        vm.resetGasMetering();
        BLSUtils.mul(g2A, BLSUtils._u(1234));
    }

    function testG2MSMGas() public {
        BLS.G2Point[] memory points = new BLS.G2Point[](2);
        points[0] = BLSUtils.sign("hello", 1234, "");
        points[1] = BLSUtils.sign("world", 5678, "");
        bytes32[] memory scalars = new bytes32[](2);
        scalars[0] = BLSUtils._u(1234);
        scalars[1] = BLSUtils._u(5678);
        vm.resetGasMetering();
        BLS.msm(points, scalars);
    }

    function testSinglePairingGas() public {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = BLSUtils.toPublicKey(1234);
        g1Points[1] = BLSUtils.toPublicKey(5678);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = BLSUtils.sign("hello", 1234, "");
        g2Points[1] = BLSUtils.sign("world", 5678, "");
        vm.resetGasMetering();
        BLS.pairing(g1Points, g2Points);
    }

    function testMapFpToG1Gas() public {
        BLS.Fp memory fp = BLS.Fp(BLSUtils._u(1234), BLSUtils._u(5678));
        vm.resetGasMetering();
        BLS.toG1(fp);
    }

    function testMapFp2ToG2Gas() public {
        BLS.Fp2 memory fp2 = BLS.Fp2(
            BLSUtils._u(1234),
            BLSUtils._u(5678),
            BLSUtils._u(91011),
            BLSUtils._u(121314)
        );
        vm.resetGasMetering();
        BLS.toG2(fp2);
    }

    function testSigningGas() public {
        BLS.G2Point memory messagePoint = BLSUtils.toMessagePoint(
            "hello",
            "domain"
        );
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(1234);
        vm.resetGasMetering();
        BLSUtils.sign("hello", 1234, "domain");
    }

    function testVerifyingSingleSignatureGas() public {
        BLS.G2Point memory messagePoint = BLSUtils.toMessagePoint(
            "hello",
            "domain"
        );
        BLS.G1Point memory publicKey = BLSUtils.toPublicKey(1234);
        BLS.G2Point memory signature = BLSUtils.sign("hello", 1234, "domain");

        vm.resetGasMetering();
        BLSUtils.verify("hello", signature, publicKey, "domain");
    }

    function testG1PointCompressGas() public {
        BLS.G1Point memory point = BLSUtils.toPublicKey(123456);
        vm.resetGasMetering();
        BLSUtils.compress(point);
    }
}
