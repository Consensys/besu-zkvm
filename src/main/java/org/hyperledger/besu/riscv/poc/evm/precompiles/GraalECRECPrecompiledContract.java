/*
 * Copyright contributors to Hyperledger Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.riscv.poc.evm.precompiles;

import org.hyperledger.besu.crypto.Hash;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.ECRECPrecompiledContract;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1Graal;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.apache.tuweni.bytes.MutableBytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GraalVM native implementation of the ECRECOVER precompiled contract.
 *
 * <p>This implementation extends the standard ECRECPrecompiledContract and overrides the compute
 * method to use LibSecp256k1Graal for native execution compatible with GraalVM native image
 * compilation.
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

    LOG.info("-----------------------------------");
    LOG.info("USING GraalECRECPrecompiledContract");
    LOG.info("-----------------------------------");
    final int size = input.size();
    final Bytes safeInput =
        size >= 128 ? input : Bytes.wrap(input, MutableBytes.create(128 - size));

    // Validate that bytes 32-62 are zero (v is in byte 63)
    if (!safeInput.slice(32, 31).isZero()) {
      return PrecompileContractResult.success(Bytes.EMPTY);
    }

    try {
      final Bytes32 messageHash = Bytes32.wrap(safeInput, 0);
      final int recId = safeInput.get(63) - V_BASE;

      // Extract the 64-byte signature (r and s)
      final byte[] sigBytes = safeInput.slice(64, 64).toArrayUnsafe();

      // Call the GraalVM-compatible native recovery function
      final byte[] recoveredPubkey =
          LibSecp256k1Graal.ecdsaRecover(
              LibSecp256k1Graal.getContext(), sigBytes, messageHash.toArrayUnsafe(), recId);

      if (recoveredPubkey == null) {
        return PrecompileContractResult.success(Bytes.EMPTY);
      }

      // The recovered pubkey is in internal 64-byte format
      // Serialize to uncompressed format (65 bytes with 0x04 prefix)
      final byte[] serialized =
          LibSecp256k1Graal.ecPubkeySerialize(
              LibSecp256k1Graal.getContext(), recoveredPubkey, false);

      if (serialized == null || serialized.length != 65) {
        return PrecompileContractResult.success(Bytes.EMPTY);
      }

      // Hash the 64-byte public key (skip the 0x04 prefix)
      final Bytes32 hashed = Hash.keccak256(Bytes.wrap(serialized).slice(1));

      // Return the last 20 bytes as the address (right-padded to 32 bytes)
      final MutableBytes32 result = MutableBytes32.create();
      hashed.slice(12).copyTo(result, 12);

      return PrecompileContractResult.success(result);

    } catch (final IllegalArgumentException e) {
      LOG.debug("ECRECOVER failed with illegal argument", e);
      return PrecompileContractResult.success(Bytes.EMPTY);
    } catch (final Exception e) {
      LOG.error("ECRECOVER failed with unexpected error", e);
      return PrecompileContractResult.success(Bytes.EMPTY);
    }
  }
}
