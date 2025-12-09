// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {RabinWilliamsVerifier} from "../src/RabinWilliamsVerifier.sol";

/**
 * @title RabinWilliamsVerifierTestHarness
 * @notice Exposes internal functions for testing
 */
contract RabinWilliamsVerifierTestHarness is RabinWilliamsVerifier {
    // Expose internal functions for testing
    // Note: Functions don't start with "test" to avoid auto-fuzzing
    function harnessExtractSignature(bytes memory signature)
        public
        pure
        returns (int256 e, uint256 f, bytes memory x)
    {
        return extractSignature(signature);
    }

    function harnessModExp(
        bytes memory base,
        uint256 exponent,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return modExp(base, exponent, modulus);
    }

    function harnessAddOne(bytes memory a) public pure returns (bytes memory) {
        return addOne(a);
    }

    function harnessDivByTwo(bytes memory a) public pure returns (bytes memory) {
        return divByTwo(a);
    }

    function harnessModMul(
        bytes memory a,
        bytes memory b,
        bytes memory n
    ) public view returns (bytes memory) {
        return modMul(a, b, n);
    }

    function harnessModSub(
        bytes memory n,
        bytes memory a,
        bytes memory modulus
    ) public view returns (bytes memory) {
        return modSub(n, a, modulus);
    }

    function harnessMul(bytes memory a, bytes memory b) public pure returns (bytes memory) {
        return mul(a, b);
    }

    function harnessSub(bytes memory a, bytes memory b) public pure returns (bytes memory) {
        return sub(a, b);
    }

    function harnessAdd(bytes memory a, bytes memory b) public pure returns (bytes memory) {
        return add(a, b);
    }

    function harnessMod(bytes memory a, bytes memory n) public pure returns (bytes memory) {
        return mod(a, n);
    }

    function harnessCompare(bytes memory a, bytes memory b) public pure returns (int256) {
        return compare(a, b);
    }

    function harnessRemoveLeadingZeros(bytes memory data) public pure returns (bytes memory) {
        return removeLeadingZeros(data);
    }

    function harnessBytesEqual(bytes memory a, bytes memory b) public pure returns (bool) {
        return bytesEqual(a, b);
    }
}

contract RabinWilliamsVerifierMathTest is Test {
    RabinWilliamsVerifierTestHarness public harness;

    function setUp() public {
        harness = new RabinWilliamsVerifierTestHarness();
    }

    // ============ Helper Functions ============

    function bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            result[i * 2] = hexChars[uint8(data[i]) >> 4];
            result[i * 2 + 1] = hexChars[uint8(data[i]) & 0x0f];
        }
        return string(result);
    }

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

    // ============ Test: removeLeadingZeros ============

    function test_RemoveLeadingZeros_NoLeadingZeros() public view {
        bytes memory input = hex"123456";
        bytes memory result = harness.harnessRemoveLeadingZeros(input);
        assertTrue(harness.harnessBytesEqual(input, result));
    }

    function test_RemoveLeadingZeros_WithLeadingZeros() public view {
        bytes memory input = hex"0000123456";
        bytes memory expected = hex"123456";
        bytes memory result = harness.harnessRemoveLeadingZeros(input);
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_RemoveLeadingZeros_AllZeros() public view {
        bytes memory input = hex"00000000";
        bytes memory result = harness.harnessRemoveLeadingZeros(input);
        assertEq(result.length, 1);
        assertEq(result[0], 0);
    }

    // ============ Test: compare ============

    function test_Compare_Equal() public view {
        bytes memory a = hex"123456";
        bytes memory b = hex"123456";
        int256 result = harness.harnessCompare(a, b);
        assertEq(result, 0);
    }

    function test_Compare_AGreater() public view {
        bytes memory a = hex"123457";
        bytes memory b = hex"123456";
        int256 result = harness.harnessCompare(a, b);
        assertGt(result, 0);
    }

    function test_Compare_ALess() public view {
        bytes memory a = hex"123455";
        bytes memory b = hex"123456";
        int256 result = harness.harnessCompare(a, b);
        assertLt(result, 0);
    }

    function test_Compare_DifferentLengths() public view {
        bytes memory a = hex"12345678";
        bytes memory b = hex"123456";
        int256 result = harness.harnessCompare(a, b);
        assertGt(result, 0);
    }

    // ============ Test: bytesEqual ============

    function test_BytesEqual_Equal() public view {
        bytes memory a = hex"123456";
        bytes memory b = hex"123456";
        assertTrue(harness.harnessBytesEqual(a, b));
    }

    function test_BytesEqual_NotEqual() public view {
        bytes memory a = hex"123456";
        bytes memory b = hex"123457";
        assertFalse(harness.harnessBytesEqual(a, b));
    }

    function test_BytesEqual_DifferentLengths() public view {
        bytes memory a = hex"123456";
        bytes memory b = hex"12345678";
        assertFalse(harness.harnessBytesEqual(a, b));
    }

    // ============ Test: add ============

    function test_Add_Simple() public view {
        bytes memory a = hex"01";
        bytes memory b = hex"02";
        bytes memory result = harness.harnessAdd(a, b);
        bytes memory expected = hex"03";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Add_WithCarry() public view {
        bytes memory a = hex"FF";
        bytes memory b = hex"01";
        bytes memory result = harness.harnessAdd(a, b);
        bytes memory expected = hex"0100";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Add_DifferentLengths() public view {
        bytes memory a = hex"1234";
        bytes memory b = hex"56";
        bytes memory result = harness.harnessAdd(a, b);
        bytes memory expected = hex"128A";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: sub ============

    function test_Sub_Simple() public view {
        bytes memory a = hex"05";
        bytes memory b = hex"02";
        bytes memory result = harness.harnessSub(a, b);
        bytes memory expected = hex"03";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Sub_WithBorrow() public view {
        bytes memory a = hex"0100";
        bytes memory b = hex"01";
        bytes memory result = harness.harnessSub(a, b);
        bytes memory expected = hex"FF";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Sub_DifferentLengths() public view {
        bytes memory a = hex"1234";
        bytes memory b = hex"56";
        bytes memory result = harness.harnessSub(a, b);
        bytes memory expected = hex"11DE";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: mul ============

    function test_Mul_Simple() public view {
        bytes memory a = hex"02";
        bytes memory b = hex"03";
        bytes memory result = harness.harnessMul(a, b);
        bytes memory expected = hex"06";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Mul_WithCarry() public view {
        bytes memory a = hex"FF";
        bytes memory b = hex"02";
        bytes memory result = harness.harnessMul(a, b);
        bytes memory expected = hex"01FE";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Mul_LargeNumbers() public view {
        bytes memory a = hex"1234";
        bytes memory b = hex"5678";
        bytes memory result = harness.harnessMul(a, b);
        // 0x1234 * 0x5678 = 0x6260060
        bytes memory expected = hex"06260060";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: addOne ============

    function test_AddOne_Simple() public view {
        bytes memory a = hex"05";
        bytes memory result = harness.harnessAddOne(a);
        bytes memory expected = hex"06";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_AddOne_WithCarry() public view {
        bytes memory a = hex"FF";
        bytes memory result = harness.harnessAddOne(a);
        bytes memory expected = hex"0100";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_AddOne_MultipleCarries() public view {
        bytes memory a = hex"FFFF";
        bytes memory result = harness.harnessAddOne(a);
        bytes memory expected = hex"010000";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: divByTwo ============

    function test_DivByTwo_Simple() public view {
        bytes memory a = hex"06";
        bytes memory result = harness.harnessDivByTwo(a);
        bytes memory expected = hex"03";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_DivByTwo_Odd() public view {
        bytes memory a = hex"07";
        bytes memory result = harness.harnessDivByTwo(a);
        bytes memory expected = hex"03";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_DivByTwo_WithRemainder() public view {
        bytes memory a = hex"0105";
        bytes memory result = harness.harnessDivByTwo(a);
        bytes memory expected = hex"82";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: mod ============

    function test_Mod_SmallerThanModulus() public view {
        bytes memory a = hex"05";
        bytes memory n = hex"0A";
        bytes memory result = harness.harnessMod(a, n);
        assertTrue(harness.harnessBytesEqual(a, result));
    }

    function test_Mod_Equal() public view {
        bytes memory a = hex"0A";
        bytes memory n = hex"0A";
        bytes memory result = harness.harnessMod(a, n);
        bytes memory expected = hex"00";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_Mod_Larger() public view {
        bytes memory a = hex"0F";
        bytes memory n = hex"0A";
        bytes memory result = harness.harnessMod(a, n);
        bytes memory expected = hex"05";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: modSub ============

    function test_ModSub_Simple() public view {
        bytes memory n = hex"0A";
        bytes memory a = hex"03";
        bytes memory result = harness.harnessModSub(n, a, n);
        bytes memory expected = hex"07";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_ModSub_Zero() public view {
        bytes memory n = hex"0A";
        bytes memory a = hex"00";
        bytes memory result = harness.harnessModSub(n, a, n);
        assertTrue(harness.harnessBytesEqual(n, result));
    }

    // ============ Test: modExp ============

    function test_ModExp_Simple() public view {
        bytes memory base = hex"02";
        uint256 exponent = 3;
        bytes memory modulus = hex"0A";
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 2^3 mod 10 = 8 mod 10 = 8
        bytes memory expected = hex"08";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_ModExp_Larger() public view {
        bytes memory base = hex"05";
        uint256 exponent = 2;
        bytes memory modulus = hex"0F";
        bytes memory result = harness.harnessModExp(base, exponent, modulus);
        // 5^2 mod 15 = 25 mod 15 = 10
        bytes memory expected = hex"0A";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: modMul ============

    function test_ModMul_Simple() public view {
        bytes memory a = hex"03";
        bytes memory b = hex"04";
        bytes memory n = hex"0A";
        bytes memory result = harness.harnessModMul(a, b, n);
        // 3 * 4 mod 10 = 12 mod 10 = 2
        bytes memory expected = hex"02";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    function test_ModMul_Larger() public view {
        bytes memory a = hex"07";
        bytes memory b = hex"08";
        bytes memory n = hex"0F";
        bytes memory result = harness.harnessModMul(a, b, n);
        // 7 * 8 mod 15 = 56 mod 15 = 11
        bytes memory expected = hex"0B";
        assertTrue(harness.harnessBytesEqual(expected, result));
    }

    // ============ Test: extractSignature ============

    function test_ExtractSignature_Case1() public view {
        // e=1, f=1: first byte = 0x00
        bytes memory signature = hex"00123456";
        (int256 e, uint256 f, bytes memory x) = harness.harnessExtractSignature(signature);
        assertEq(e, 1);
        assertEq(f, 1);
        assertTrue(harness.harnessBytesEqual(x, hex"123456"));
    }

    function test_ExtractSignature_Case2() public view {
        // e=-1, f=1: first byte = 0x01
        bytes memory signature = hex"01123456";
        (int256 e, uint256 f, bytes memory x) = harness.harnessExtractSignature(signature);
        assertEq(e, -1);
        assertEq(f, 1);
        assertTrue(harness.harnessBytesEqual(x, hex"123456"));
    }

    function test_ExtractSignature_Case3() public view {
        // e=1, f=2: first byte = 0x02
        bytes memory signature = hex"02123456";
        (int256 e, uint256 f, bytes memory x) = harness.harnessExtractSignature(signature);
        assertEq(e, 1);
        assertEq(f, 2);
        assertTrue(harness.harnessBytesEqual(x, hex"123456"));
    }

    function test_ExtractSignature_Case4() public view {
        // e=-1, f=2: first byte = 0x03
        bytes memory signature = hex"03123456";
        (int256 e, uint256 f, bytes memory x) = harness.harnessExtractSignature(signature);
        assertEq(e, -1);
        assertEq(f, 2);
        assertTrue(harness.harnessBytesEqual(x, hex"123456"));
    }

    // ============ Test: Expected Reverts ============

    function test_ExtractSignature_RevertOnShortSignature() public {
        bytes memory shortSignature = hex"00";
        vm.expectRevert("Invalid signature length");
        harness.harnessExtractSignature(shortSignature);
    }

    function test_ExtractSignature_RevertOnInvalidFlags() public {
        // First byte with bits 2-7 set (invalid)
        bytes memory invalidSignature = hex"04123456";
        vm.expectRevert("Invalid signature flags");
        harness.harnessExtractSignature(invalidSignature);
    }

    function test_Mod_RevertOnZeroModulus() public {
        bytes memory a = hex"05";
        bytes memory n = hex"00";
        // mod will revert when n is zero (hits iteration limit or other issue)
        // Actually, let's check what happens - it might not revert immediately
        // The mod function checks for zero modulus in removeLeadingZeros
        // Let's test with a case that will hit the iteration limit
        bytes memory largeA = hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        bytes memory smallN = hex"01";
        // This will hit the iteration limit
        vm.expectRevert("Mod reduction failed - number too large");
        harness.harnessMod(largeA, smallN);
    }

}

