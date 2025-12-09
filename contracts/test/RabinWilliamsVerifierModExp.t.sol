// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {RabinWilliamsVerifier} from "../src/RabinWilliamsVerifier.sol";

/**
 * @title RabinWilliamsVerifierModExpTestHarness
 * @notice Exposes modExp for detailed testing
 */
contract RabinWilliamsVerifierModExpTestHarness is RabinWilliamsVerifier {
    function harnessModExp(
        bytes memory base,
        uint256 exponent,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return modExp(base, exponent, modulus);
    }

    function harnessCompare(bytes memory a, bytes memory b) public pure returns (int256) {
        return compare(a, b);
    }

    function harnessBytesEqual(bytes memory a, bytes memory b) public pure returns (bool) {
        return bytesEqual(a, b);
    }

    function harnessRemoveLeadingZeros(bytes memory data) public pure returns (bytes memory) {
        return removeLeadingZeros(data);
    }
}

contract RabinWilliamsVerifierModExpTest is Test {
    RabinWilliamsVerifierModExpTestHarness public harness;

    function setUp() public {
        harness = new RabinWilliamsVerifierModExpTestHarness();
    }

    // ============ Helper Functions ============

    function hexToBytes(string memory hexString) internal pure returns (bytes memory) {
        bytes memory hexBytes = bytes(hexString);
        require(hexBytes.length % 2 == 0, "Invalid hex string length");
        
        bytes memory result = new bytes(hexBytes.length / 2);
        for (uint256 i = 0; i < result.length; i++) {
            uint8 high = charToHex(hexBytes[i * 2]);
            uint8 low = charToHex(hexBytes[i * 2 + 1]);
            result[i] = bytes1((high << 4) | low);
        }
        return result;
    }

    function charToHex(bytes1 char) internal pure returns (uint8) {
        if (char >= 0x30 && char <= 0x39) {
            return uint8(char) - 0x30;
        } else if (char >= 0x41 && char <= 0x46) {
            return uint8(char) - 0x37;
        } else if (char >= 0x61 && char <= 0x66) {
            return uint8(char) - 0x57;
        }
        revert("Invalid hex character");
    }

    // ============ Test: Basic modExp Operations ============

    function test_ModExp_Exponent1() public view {
        // base^1 mod modulus = base mod modulus
        bytes memory base = hex"0F"; // 15
        uint256 exponent = 1;
        bytes memory modulus = hex"0A"; // 10
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"05"; // 15 mod 10 = 5
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_Exponent2() public view {
        // base^2 mod modulus
        bytes memory base = hex"05"; // 5
        uint256 exponent = 2;
        bytes memory modulus = hex"0F"; // 15
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"0A"; // 5^2 = 25, 25 mod 15 = 10
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_Exponent3() public view {
        // base^3 mod modulus
        bytes memory base = hex"02"; // 2
        uint256 exponent = 3;
        bytes memory modulus = hex"0A"; // 10
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"08"; // 2^3 = 8, 8 mod 10 = 8
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_LargeExponent() public view {
        // base^10 mod modulus
        bytes memory base = hex"03"; // 3
        uint256 exponent = 10;
        bytes memory modulus = hex"0F"; // 15
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 3^10 = 59049, 59049 mod 15 = 9
        bytes memory expected = hex"09";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Edge Cases ============

    function test_ModExp_BaseEqualsModulus() public view {
        // base = modulus, result should be 0
        bytes memory base = hex"0A";
        uint256 exponent = 2;
        bytes memory modulus = hex"0A";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"00";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_BaseLargerThanModulus() public view {
        // base > modulus, should be reduced first
        bytes memory base = hex"0F"; // 15
        uint256 exponent = 2;
        bytes memory modulus = hex"0A"; // 10
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 15 mod 10 = 5, 5^2 = 25, 25 mod 10 = 5
        bytes memory expected = hex"05";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_ResultSmallerThanModulus() public view {
        // Verify result is always < modulus
        bytes memory base = hex"02";
        uint256 exponent = 4;
        bytes memory modulus = hex"0F";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 2^4 = 16, 16 mod 15 = 1
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
        
        // Verify result < modulus
        assertLt(harness.harnessCompare(result, modulus), 0);
    }

    function test_ModExp_ExponentZero() public view {
        // base^0 mod modulus = 1 mod modulus
        bytes memory base = hex"05";
        uint256 exponent = 0;
        bytes memory modulus = hex"0A";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Different Sizes ============

    function test_ModExp_SingleByte() public view {
        bytes memory base = hex"03";
        uint256 exponent = 2;
        bytes memory modulus = hex"07";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"02"; // 3^2 = 9, 9 mod 7 = 2
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_TwoBytes() public view {
        bytes memory base = hex"0100"; // 256
        uint256 exponent = 2;
        bytes memory modulus = hex"00FF"; // 255
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 256 mod 255 = 1, 1^2 = 1, 1 mod 255 = 1
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_ThreeBytes() public view {
        bytes memory base = hex"010000"; // 65536
        uint256 exponent = 2;
        bytes memory modulus = hex"00FFFF"; // 65535
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 65536 mod 65535 = 1, 1^2 = 1, 1 mod 65535 = 1
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Specific to Rabin-Williams (x^2 mod n) ============

    function test_ModExp_XSquared_Small() public view {
        // Test x^2 mod n with small values
        bytes memory x = hex"05"; // 5
        uint256 exponent = 2;
        bytes memory n = hex"0F"; // 15
        
        bytes memory result = harness.harnessModExp(x, exponent, n);
        bytes memory expected = hex"0A"; // 5^2 = 25, 25 mod 15 = 10
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_XSquared_Medium() public view {
        // Test with medium-sized values
        bytes memory x = hex"0100"; // 256
        uint256 exponent = 2;
        bytes memory n = hex"00FF"; // 255
        
        bytes memory result = harness.harnessModExp(x, exponent, n);
        // 256 mod 255 = 1, 1^2 = 1, 1 mod 255 = 1
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Verify Precompile Input Format ============
    // These tests verify that our input format matches what the precompile expects

    function test_ModExp_VerifyFormat_Small() public view {
        // Use a known good case to verify format is correct
        bytes memory base = hex"02";
        uint256 exponent = 3;
        bytes memory modulus = hex"0A";
        
        // Expected: 2^3 mod 10 = 8 mod 10 = 8
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"08";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_VerifyFormat_Exponent2() public view {
        // Test exponent = 2 specifically (what we use in verification)
        bytes memory base = hex"03";
        uint256 exponent = 2;
        bytes memory modulus = hex"0B";
        
        // Expected: 3^2 mod 11 = 9 mod 11 = 9
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"09";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Compare with Manual Calculation ============

    function test_ModExp_ManualCalculation1() public view {
        // 7^2 mod 13 = 49 mod 13 = 10
        bytes memory base = hex"07";
        uint256 exponent = 2;
        bytes memory modulus = hex"0D";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"0A";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    function test_ModExp_ManualCalculation2() public view {
        // 4^3 mod 7 = 64 mod 7 = 1
        bytes memory base = hex"04";
        uint256 exponent = 3;
        bytes memory modulus = hex"07";
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"01";
        assertTrue(harness.harnessBytesEqual(result, expected));
    }

    // ============ Test: Large Values (like our 1024-bit case) ============

    function test_ModExp_LargeBase() public view {
        // Test with a larger base (32 bytes = 256 bits)
        bytes memory base = hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"; // 2^256 - 1
        uint256 exponent = 1;
        bytes memory modulus = hex"010000000000000000000000000000000000000000000000000000000000000000"; // 2^256
        
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // (2^256 - 1) mod 2^256 = 2^256 - 1 (since it's less than modulus)
        // But we need to verify it's correct
        assertLt(harness.harnessCompare(result, modulus), 0); // result < modulus
    }

    function test_ModExp_WithFixtureData() public view {
        // Test with actual fixture data to see if modExp works correctly
        string memory publicKeyHex = vm.readFile("contracts/test/fixtures/public_key.hex");
        string memory signatureHex = vm.readFile("contracts/test/fixtures/signature.hex");
        
        bytes memory n = hexToBytes(publicKeyHex);
        bytes memory signature = hexToBytes(signatureHex);
        
        // Extract x from signature (skip first byte)
        bytes memory x = new bytes(signature.length - 1);
        for (uint256 i = 1; i < signature.length; i++) {
            x[i - 1] = signature[i];
        }
        
        console.log("x length:", x.length);
        console.log("n length:", n.length);
        
        // Compute x^2 mod n
        bytes memory xSquared = harness.harnessModExp(x, 2, n);
        
        console.log("xSquared length:", xSquared.length);
        
        // Verify xSquared < n
        int256 cmp = harness.harnessCompare(xSquared, n);
        console.log("xSquared < n:", cmp < 0);
        assertLt(cmp, 0, "xSquared should be less than n");
        
        // Log first few bytes
        if (xSquared.length >= 4) {
            console.log("xSquared[0]:", uint8(xSquared[0]));
            console.log("xSquared[1]:", uint8(xSquared[1]));
            console.log("xSquared[2]:", uint8(xSquared[2]));
            console.log("xSquared[3]:", uint8(xSquared[3]));
        }
        
        // Verify result has no leading zeros (after our removeLeadingZeros)
        bytes memory cleaned = harness.harnessRemoveLeadingZeros(xSquared);
        assertEq(cleaned.length, xSquared.length, "xSquared should not have leading zeros");
    }

    // ============ Test: Verify modExp Input Format Matches EIP-198 ============
    // EIP-198 specifies the format should be:
    // baseLen (32 bytes, big-endian uint256) || expLen (32 bytes, big-endian uint256) || modLen (32 bytes, big-endian uint256) ||
    // base (baseLen bytes) || exponent (expLen bytes, big-endian) || modulus (modLen bytes)

    function test_ModExp_InputFormat_Validation() public view {
        // Test with known values to ensure our encoding matches EIP-198
        bytes memory base = hex"02";
        uint256 exponent = 3;
        bytes memory modulus = hex"0A";
        
        // This should work if our format is correct
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        bytes memory expected = hex"08"; // 2^3 mod 10 = 8
        assertTrue(harness.harnessBytesEqual(result, expected), "modExp format validation failed");
    }

    function test_ModExp_ExponentEncoding() public view {
        // Verify that exponent is encoded correctly as 32-byte big-endian
        // Test with exponent = 1, 2, and a larger value
        bytes memory base = hex"03";
        bytes memory modulus = hex"0B";
        
        // exponent = 1
        bytes memory result1 = harness.harnessModExp(base, 1, modulus);
        bytes memory expected1 = hex"03"; // 3^1 mod 11 = 3
        assertTrue(harness.harnessBytesEqual(result1, expected1));
        
        // exponent = 2
        bytes memory result2 = harness.harnessModExp(base, 2, modulus);
        bytes memory expected2 = hex"09"; // 3^2 mod 11 = 9
        assertTrue(harness.harnessBytesEqual(result2, expected2));
        
        // exponent = 256 (tests that large exponents work)
        bytes memory result3 = harness.harnessModExp(base, 256, modulus);
        // 3^256 mod 11 - we just verify it's < modulus
        assertLt(harness.harnessCompare(result3, modulus), 0);
    }

    function test_ModExp_LengthEncoding() public view {
        // Verify that length fields are encoded as 32-byte big-endian uint256
        // Test with different base/modulus sizes
        bytes memory base1 = hex"02"; // 1 byte
        bytes memory modulus1 = hex"0A"; // 1 byte
        bytes memory result1 = harness.harnessModExp(base1, 2, modulus1);
        bytes memory expected1 = hex"04"; // 2^2 mod 10 = 4
        assertTrue(harness.harnessBytesEqual(result1, expected1));
        
        bytes memory base2 = hex"0100"; // 2 bytes
        bytes memory modulus2 = hex"00FF"; // 2 bytes
        bytes memory result2 = harness.harnessModExp(base2, 2, modulus2);
        // 256 mod 255 = 1, 1^2 = 1, 1 mod 255 = 1
        bytes memory expected2 = hex"01";
        assertTrue(harness.harnessBytesEqual(result2, expected2));
    }
}

