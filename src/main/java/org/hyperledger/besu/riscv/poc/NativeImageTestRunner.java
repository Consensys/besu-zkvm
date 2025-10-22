/*
 * Copyright Consensys Software Inc., 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.hyperledger.besu.riscv.poc;

/**
 * Main test runner for GraalVM native-image test cases. Provides a command-line interface to run
 * various tests that exercise native-image corner cases with different libraries.
 */
public class NativeImageTestRunner {

  /**
   * Main entry point for the test runner.
   *
   * @param args command line arguments - test name to run
   */
  public static void main(String[] args) {
    if (args.length == 0) {
      printUsage();
      System.exit(1);
    }

    String testName = args[0].toLowerCase();

    try {
      switch (testName) {
        case "all":
          System.out.println("Running all tests...\n");
          runBouncyCastleR1Test();
          System.out.println();
          runGnarkG2PointTest();
          System.out.println();
          runSecp256k1GraalTest();
          System.out.println();
          runP256VerifyGraalTest();
          break;
        case "bouncycastler1":
          runBouncyCastleR1Test();
          break;
        case "gnarkg2point":
          runGnarkG2PointTest();
          break;
        case "secp256k1graal":
          runSecp256k1GraalTest();
          break;
        case "p256verify":
          runP256VerifyGraalTest();
          break;
        default:
          System.err.println("Unknown test: " + testName);
          System.err.println();
          printUsage();
          System.exit(1);
      }
    } catch (Exception e) {
      System.err.println("Test execution failed: " + e.getMessage());
      e.printStackTrace();
      System.exit(1);
    }
  }

  /** Prints usage information. */
  private static void printUsage() {
    System.out.println("Usage: NativeImageTestRunner <test-name>");
    System.out.println();
    System.out.println("Available tests:");
    System.out.println("  all              - Run all tests");
    System.out.println(
        "  bouncyCastleR1   - Test BouncyCastle secp256r1 key generation and signing");
    System.out.println("  gnarkG2Point     - Test Gnark BLS12-381 G2 point validation");
    System.out.println("  secp256k1Graal   - Test SECP256K1 with LibSecp256k1Graal native library");
    System.out.println("  p256Verify       - Test P-256 signature verification with BoringSSL");
    System.out.println();
    System.out.println("Examples:");
    System.out.println("  NativeImageTestRunner all");
    System.out.println("  NativeImageTestRunner bouncyCastleR1");
    System.out.println("  NativeImageTestRunner gnarkG2Point");
    System.out.println("  NativeImageTestRunner secp256k1Graal");
    System.out.println("  NativeImageTestRunner p256Verify");
  }

  /** Runs the BouncyCastle R1 test. */
  private static void runBouncyCastleR1Test() throws Exception {
    System.out.println("========================================");
    System.out.println("BouncyCastle secp256r1 Test");
    System.out.println("========================================");
    BouncyCastleR1Test.runTest();
  }

  /** Runs the Gnark G2 point test. */
  private static void runGnarkG2PointTest() {
    System.out.println("========================================");
    System.out.println("Gnark BLS12-381 G2 Point Test");
    System.out.println("========================================");
    GnarkG2PointTest.runTest();
  }

  /** Runs the SECP256K1 Graal test. */
  private static void runSecp256k1GraalTest() throws Exception {
    System.out.println("========================================");
    System.out.println("SECP256K1 LibSecp256k1Graal Test");
    System.out.println("========================================");
    Secp256k1GraalTest.runTest();
  }

  /** Runs the P-256 verify test. */
  private static void runP256VerifyGraalTest() throws Exception {
    System.out.println("========================================");
    System.out.println("P-256 Signature Verification Test");
    System.out.println("========================================");
    P256VerifyGraalTest.runTest();
  }
}
