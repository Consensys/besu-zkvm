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

import static java.nio.charset.StandardCharsets.UTF_8;

import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;
import org.hyperledger.besu.nativelib.gnark.LibGnarkEIP196Graal;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.type.CIntPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * GraalVM-compatible AltBN128 pairing check precompiled contract (Byzantium version).
 *
 * <p>This implementation uses LibGnarkEIP196Graal for native execution compatible with GraalVM
 * native image compilation.
 */
public class GraalAltBN128PairingPrecompiledContract extends AbstractPrecompiledContract {

  private static final Logger LOG =
      LoggerFactory.getLogger(GraalAltBN128PairingPrecompiledContract.class);

  private static final int PARAMETER_LENGTH = 192;
  private static final long PAIRING_GAS_COST = 80_000L; // Byzantium per-pairing cost
  private static final long BASE_GAS_COST = 100_000L; // Byzantium base cost

  /** The constant TRUE (pairing check succeeded). */
  public static final Bytes TRUE =
      Bytes.fromHexString("0x0000000000000000000000000000000000000000000000000000000000000001");

  /**
   * Instantiates a new Graal AltBN128 Pairing precompiled contract.
   *
   * @param gasCalculator the gas calculator
   */
  public GraalAltBN128PairingPrecompiledContract(final GasCalculator gasCalculator) {
    super("AltBN128Pairing", gasCalculator);
  }

  @Override
  public long gasRequirement(final Bytes input) {
    final int parameters = input.size() / PARAMETER_LENGTH;
    return (PAIRING_GAS_COST * parameters) + BASE_GAS_COST;
  }

  @Override
  public PrecompileContractResult computePrecompile(
      final Bytes input, final MessageFrame messageFrame) {

    // Empty input is valid and returns TRUE
    if (input.isEmpty()) {
      return PrecompileContractResult.success(TRUE);
    }

    final byte[] result = new byte[LibGnarkEIP196Graal.EIP196_PREALLOCATE_FOR_RESULT_BYTES];
    final byte[] error = new byte[LibGnarkEIP196Graal.EIP196_PREALLOCATE_FOR_ERROR_BYTES];
    final int[] outputSize = new int[1];
    final int[] errorSize = new int[1];

    outputSize[0] = LibGnarkEIP196Graal.EIP196_PREALLOCATE_FOR_RESULT_BYTES;
    errorSize[0] = LibGnarkEIP196Graal.EIP196_PREALLOCATE_FOR_ERROR_BYTES;

    // Calculate input limit (must be multiple of PARAMETER_LENGTH)
    final int inputLimit = (Integer.MAX_VALUE / PARAMETER_LENGTH) * PARAMETER_LENGTH;
    final int inputSize = Math.min(inputLimit, input.size());
    final byte[] inputBytes = input.slice(0, inputSize).toArrayUnsafe();

    try (PinnedObject pinnedInput = PinnedObject.create(inputBytes);
        PinnedObject pinnedResult = PinnedObject.create(result);
        PinnedObject pinnedError = PinnedObject.create(error);
        PinnedObject pinnedOutputSize = PinnedObject.create(outputSize);
        PinnedObject pinnedErrorSize = PinnedObject.create(errorSize)) {

      final int errorNo =
          LibGnarkEIP196Graal.eip196altbn128PairingNative(
              pinnedInput.addressOfArrayElement(0),
              pinnedResult.addressOfArrayElement(0),
              pinnedError.addressOfArrayElement(0),
              inputSize,
              (CIntPointer) pinnedOutputSize.addressOfArrayElement(0),
              (CIntPointer) pinnedErrorSize.addressOfArrayElement(0));

      if (errorNo == 0) {
        return PrecompileContractResult.success(Bytes.wrap(result, 0, outputSize[0]));
      } else {
        final String errorString = new String(error, 0, errorSize[0], UTF_8);
        messageFrame.setRevertReason(Bytes.wrap(error, 0, errorSize[0]));
        LOG.trace("Error executing AltBN128 Pairing precompile: '{}'", errorString);
        return PrecompileContractResult.halt(
            null, Optional.of(ExceptionalHaltReason.PRECOMPILE_ERROR));
      }
    }
  }
}
