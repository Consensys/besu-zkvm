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
package org.hyperledger.besu.riscv.poc.evm.precompiles;

import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.ECRECPrecompiledContract;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1EcrecoverGraal;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.apache.tuweni.bytes.MutableBytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GraalVM native implementation of the ECRECOVER precompiled contract.
 *
 * <p>This implementation uses LibSecp256k1EcrecoverGraal which provides the same interface as the
 * JNI version but is compatible with GraalVM native image compilation.
 */
public class GraalECRECPrecompiledContract extends ECRECPrecompiledContract {

  private static final Logger LOG = LoggerFactory.getLogger(GraalECRECPrecompiledContract.class);
  private static final int V_BASE = 27;

  /**
   * Instantiates a new Graal ECREC precompiled contract.
   *
   * @param gasCalculator the gas calculator
   */
  public GraalECRECPrecompiledContract(final GasCalculator gasCalculator) {
    super(gasCalculator);
  }

  @Override
  public PrecompileContractResult computePrecompile(
      final Bytes input, final MessageFrame messageFrame) {

    LOG.debug("===========================================");
    LOG.debug("ECREC CALLED");
    LOG.debug("  Transaction: {}", messageFrame.getOriginatorAddress());
    LOG.debug("  Recipient: {}", messageFrame.getRecipientAddress());
    LOG.debug("  Contract: {}", messageFrame.getContractAddress());
    LOG.debug("===========================================");

    final int size = input.size();
    final Bytes safeInput =
        size >= 128 ? input : Bytes.wrap(input, MutableBytes.create(128 - size));

    // Validate that bytes 32-62 are zero (v is in byte 63)
    if (!safeInput.slice(32, 31).isZero()) {
      LOG.debug("ECREC: bytes 32-62 are not zero, returning empty");
      return PrecompileContractResult.success(Bytes.EMPTY);
    }

    try {
      final Bytes32 messageHash = Bytes32.wrap(safeInput, 0);
      final int recId = safeInput.get(63) - V_BASE;
      final byte[] sigBytes = safeInput.slice(64, 64).toArrayUnsafe();

      LOG.atDebug()
          .setMessage("ECREC: messageHash={}, recId={}, sigBytes length={}")
          .addArgument(messageHash::toHexString)
          .addArgument(recId)
          .addArgument(() -> sigBytes.length)
          .log();

      // Call LibSecp256k1EcrecoverGraal which returns a 65-byte uncompressed public key
      // This matches the JNI version exactly
      final byte[] recoveredPubkey =
          LibSecp256k1EcrecoverGraal.secp256k1EcrecoverWithAlloc(
              messageHash.toArrayUnsafe(), sigBytes, recId);

      if (recoveredPubkey == null) {
        LOG.debug("ECREC: Recovery failed, returning empty");
        return PrecompileContractResult.success(Bytes.EMPTY);
      }

      LOG.atDebug()
          .setMessage("ECREC: Recovered 65-byte pubkey, first byte: 0x{}")
          .addArgument(() -> String.format("%02x", recoveredPubkey[0]))
          .log();

      // Strip the 0x04 prefix to get the 64-byte public key (X || Y coordinates)
      // Then hash it to derive the Ethereum address
      // final byte[] publicKey = new byte[64];
      // System.arraycopy(recoveredPubkey, 1, publicKey, 0, 64);
      // final Bytes32 hashed = Hash.keccak256(Bytes.wrap(publicKey));

      final Bytes32 hashed = Hash.keccak256(Bytes.wrap(recoveredPubkey).slice(1));

      // Return the last 20 bytes as the address (right-padded to 32 bytes)
      final MutableBytes32 result = MutableBytes32.create();
      hashed.slice(12).copyTo(result, 12);

      LOG.atDebug()
          .setMessage("ECREC: Success, returning result={}")
          .addArgument(result::toHexString)
          .log();
      return PrecompileContractResult.success(result);

    } catch (final IllegalArgumentException e) {
      LOG.error("ECRECOVER failed with illegal argument", e);
      return PrecompileContractResult.success(Bytes.EMPTY);
    } catch (final Throwable e) {
      LOG.error("ECRECOVER failed with unexpected error", e);
      return PrecompileContractResult.success(Bytes.EMPTY);
    }
  }
}
