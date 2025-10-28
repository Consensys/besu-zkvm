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

import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;

import org.apache.tuweni.bytes.Bytes;

/**
 * Mock precompiled contract that logs when called and throws UnsupportedOperationException.
 *
 * <p>This is used to identify which precompiles are actually being invoked during block processing
 * without implementing the full precompile logic.
 */
public class MockPrecompiledContract extends AbstractPrecompiledContract {

  private final String name;

  /**
   * Instantiates a new Mock precompiled contract.
   *
   * @param name the name of the precompile for logging
   * @param gasCalculator the gas calculator
   */
  public MockPrecompiledContract(final String name, final GasCalculator gasCalculator) {
    super(name, gasCalculator);
    this.name = name;
  }

  @Override
  public long gasRequirement(final Bytes input) {
    // Return a minimal gas requirement to avoid gas estimation failures
    return 100L;
  }

  @Override
  public PrecompileContractResult computePrecompile(
      final Bytes input, final MessageFrame messageFrame) {
    System.out.println("===========================================");
    System.out.println("MOCK PRECOMPILE CALLED: " + name);
    System.out.println("Input length: " + input.size());
    System.out.println("Input (hex): " + input.toHexString());
    System.out.println("===========================================");

    throw new UnsupportedOperationException(
        "Precompile " + name + " is not implemented (mock only)");
  }
}
