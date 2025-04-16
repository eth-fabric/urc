// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;
// Credit: https://github.com/paradigmxyz/forge-alphanet/blob/main/src/sign/BLS.sol

import { Test, console } from "forge-std/Test.sol";
import { BLS } from "../src/lib/BLS.sol";

/// @notice A simple test demonstrating BLS signature verification.
contract BLSTest is Test {
    /// @dev Demonstrates the signing and verification of a message.
    function testSignAndVerify(uint256 privateKey, bytes memory message, bytes memory domainSeparator) public view {
        BLS.G1Point memory publicKey = BLS.toPublicKey(privateKey);
        BLS.G2Point memory signature = BLS.sign(message, privateKey, domainSeparator);
        assert(BLS.verify(message, signature, publicKey, domainSeparator));
    }

    /// @dev Demonstrates the aggregation and verification of two signatures.
    function testAggregation(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes memory message,
        bytes memory domainSeparator
    ) public view {
        // public keys
        BLS.G1Point memory pk1 = BLS.toPublicKey(privateKey1);
        BLS.G1Point memory pk2 = BLS.toPublicKey(privateKey2);

        // signatures
        BLS.G2Point memory sig1 = BLS.sign(message, privateKey1, domainSeparator);
        BLS.G2Point memory sig2 = BLS.sign(message, privateKey2, domainSeparator);

        // aggregated signature
        BLS.G2Point memory sig = BLS.G2Add(sig1, sig2);

        // Invoke the pairing check to verify the signature.
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](3);
        g1Points[0] = BLS.NEGATED_G1_GENERATOR();
        g1Points[1] = pk1;
        g1Points[2] = pk2;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](3);
        g2Points[0] = sig;
        g2Points[1] = BLS.toMessagePoint(message, domainSeparator);
        g2Points[2] = BLS.toMessagePoint(message, domainSeparator);

        assert(BLS.Pairing(g1Points, g2Points));
    }

    function testToMessagePoint(bytes memory message, bytes memory domainSeparator) public view {
        BLS.G2Point memory messagePoint = BLS.toMessagePoint(message, domainSeparator);
        BLS.G2Point memory messagePointExpected = BLS.MapFp2ToG2(
            BLS.Fp2(BLS.Fp(0, 0), BLS.Fp(0, uint256(keccak256(abi.encodePacked(domainSeparator, message)))))
        );

        assert(
            messagePoint.x.c0.a == messagePointExpected.x.c0.a && messagePoint.x.c0.b == messagePointExpected.x.c0.b
                && messagePoint.x.c1.a == messagePointExpected.x.c1.a && messagePoint.x.c1.b == messagePointExpected.x.c1.b
                && messagePoint.y.c0.a == messagePointExpected.y.c0.a && messagePoint.y.c0.b == messagePointExpected.y.c0.b
                && messagePoint.y.c1.a == messagePointExpected.y.c1.a && messagePoint.y.c1.b == messagePointExpected.y.c1.b
        );
    }

    function testToPublicKey() public view {
        uint256 privateKey = 12356;

        // uncompressed public key
        BLS.G1Point memory expected = BLS.G1Point(
            BLS.Fp(
                12115118667309283734868789696201968385,
                102796267992108309135721548586500937750960769774310798537421982072779087272819
            ),
            BLS.Fp(
                15699442850880472822588013448545136667,
                697141831937854224682724016220779412457574525815594559914325383387627997986
            )
        );

        BLS.G1Point memory publicKey = BLS.toPublicKey(privateKey);
        assert(
            publicKey.x.a == expected.x.a && publicKey.x.b == expected.x.b && publicKey.y.a == expected.y.a
                && publicKey.y.b == expected.y.b
        );
    }

    function testG1PointCompress_1() public {
        BLS.G1Point memory point = BLS.toPublicKey(123456);
        BLS.Fp memory result = BLS.compress(point);

        // Expected result: 0xaf6e96c0eccd8d4ae868be9299af737855a1b08d57bccb565ea7e69311a30baeebe08d493c3fea97077e8337e95ac5a6
        assert(result.a == 233189109563333818632959426218981028728);
        assert(result.b == 38732273024956312936195524807674957651409788979825024437260187772136397129126);
    }

    function testG1PointCompress_2() public {
        BLS.G1Point memory point = BLS.toPublicKey(69420);
        BLS.Fp memory result = BLS.compress(point);
        console.log("result.a", result.a);
        console.log("result.b", result.b);

        // Expected result: 0xb9e16ee4c0c0f6fd65b48c8dc759038bd2eebd979e489d08d69825bed32a37c3cc69e9e05f577445ee27319791832961
        assert(result.a == 247077695202111629659213208963742499723);
        assert(result.b == 95407516321583900695556749922087294361570042875752728076201341488189472450913);
    }
}

contract BLSGasTest is Test {
    function testG1AddGas() public {
        BLS.G1Point memory a = BLS.toPublicKey(1234);
        BLS.G1Point memory b = BLS.toPublicKey(5678);
        vm.resetGasMetering();
        BLS.G1Add(a, b);
    }

    function testG1MulGas() public {
        BLS.G1Point memory a = BLS.toPublicKey(1234);
        vm.resetGasMetering();
        BLS.G1Mul(a, 1234);
    }

    function testG1MSMGas() public {
        BLS.G1Point[] memory points = new BLS.G1Point[](2);
        points[0] = BLS.toPublicKey(1234);
        points[1] = BLS.toPublicKey(5678);
        uint256[] memory scalars = new uint256[](2);
        scalars[0] = 1234;
        scalars[1] = 5678;
        vm.resetGasMetering();
        BLS.G1MSM(points, scalars);
    }

    function testG2AddGas() public {
        BLS.G2Point memory g2A = BLS.sign("hello", 1234, "");

        BLS.G2Point memory g2B = BLS.sign("world", 5678, "");
        vm.resetGasMetering();
        BLS.G2Add(g2A, g2B);
    }

    function testG2MulGas() public {
        BLS.G2Point memory g2A = BLS.sign("hello", 1234, "");
        vm.resetGasMetering();
        BLS.G2Mul(g2A, 1234);
    }

    function testG2MSMGas() public {
        BLS.G2Point[] memory points = new BLS.G2Point[](2);
        points[0] = BLS.sign("hello", 1234, "");
        points[1] = BLS.sign("world", 5678, "");
        uint256[] memory scalars = new uint256[](2);
        scalars[0] = 1234;
        scalars[1] = 5678;
        vm.resetGasMetering();
        BLS.G2MSM(points, scalars);
    }

    function testSinglePairingGas() public {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = BLS.toPublicKey(1234);
        g1Points[1] = BLS.toPublicKey(5678);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = BLS.sign("hello", 1234, "");
        g2Points[1] = BLS.sign("world", 5678, "");
        vm.resetGasMetering();
        BLS.Pairing(g1Points, g2Points);
    }

    function testMapFpToG1Gas() public {
        BLS.Fp memory fp = BLS.Fp(1234, 5678);
        vm.resetGasMetering();
        BLS.MapFpToG1(fp);
    }

    function testMapFp2ToG2Gas() public {
        BLS.Fp2 memory fp2 = BLS.Fp2(BLS.Fp(1234, 5678), BLS.Fp(91011, 121314));
        vm.resetGasMetering();
        BLS.MapFp2ToG2(fp2);
    }

    function testHashToCurveG2Gas() public {
        bytes memory message = "hello";
        vm.resetGasMetering();
        BLS.hashToCurveG2(message);
    }

    function testSigningGas() public {
        BLS.G2Point memory messagePoint = BLS.toMessagePoint("hello", "domain");
        vm.resetGasMetering();
        BLS.G2Mul(messagePoint, 1234);
    }

    function testVerifyingSingleSignatureGas() public {
        BLS.G2Point memory messagePoint = BLS.toMessagePoint("hello", "domain");
        BLS.G1Point memory publicKey = BLS.toPublicKey(1234);
        BLS.G2Point memory signature = BLS.sign("hello", 1234, "domain");

        vm.resetGasMetering();
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = BLS.NEGATED_G1_GENERATOR();
        g1Points[1] = publicKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = messagePoint;

        BLS.Pairing(g1Points, g2Points);
    }

    function testG1PointCompressGas() public {
        BLS.G1Point memory point = BLS.toPublicKey(123456);
        vm.resetGasMetering();
        BLS.compress(point);
    }
}
