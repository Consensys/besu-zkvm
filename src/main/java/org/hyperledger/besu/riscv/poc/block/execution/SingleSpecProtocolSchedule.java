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
package org.hyperledger.besu.riscv.poc.block.execution;

import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.PermissionTransactionFilter;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.mainnet.ScheduledProtocolSpec;
import org.hyperledger.besu.plugin.data.ProcessableBlockHeader;
import org.hyperledger.besu.plugin.services.txvalidator.TransactionValidationRule;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A minimal protocol schedule that always returns a single ProtocolSpec.
 *
 * <p>This avoids the overhead and preconditions of DefaultProtocolSchedule which requires
 * milestones at block 0 and maintains a sorted set of protocol specs for all forks. For
 * single-block processing, we only need one spec that applies to the target block.
 */
public class SingleSpecProtocolSchedule implements ProtocolSchedule {

  private static final Logger LOG = LoggerFactory.getLogger(SingleSpecProtocolSchedule.class);

  private ProtocolSpec spec;
  private final Optional<BigInteger> chainId;

  public SingleSpecProtocolSchedule(final ProtocolSpec spec, final Optional<BigInteger> chainId) {
    this.spec = spec;
    this.chainId = chainId;
    LOG.info(
        "SingleSpecProtocolSchedule constructor: spec={}, preExecutionProcessor={}",
        spec,
        spec == null ? "NULL_SPEC" : (spec.getPreExecutionProcessor() == null ? "NULL" : spec.getPreExecutionProcessor().getClass().getSimpleName()));
  }

  /**
   * Set the protocol spec. This is needed to resolve the circular dependency where
   * ProtocolSpecBuilder.build() needs a ProtocolSchedule, but we need the built ProtocolSpec to
   * populate the schedule.
   *
   * @param protocolSpec the protocol spec to set
   */
  public void setProtocolSpec(final ProtocolSpec protocolSpec) {
    LOG.info(
        "setProtocolSpec called: preExecutionProcessor={}",
        protocolSpec == null ? "NULL_SPEC" : (protocolSpec.getPreExecutionProcessor() == null ? "NULL" : protocolSpec.getPreExecutionProcessor().getClass().getSimpleName()));
    this.spec = protocolSpec;
  }

  @Override
  public ProtocolSpec getByBlockHeader(final ProcessableBlockHeader blockHeader) {
    LOG.info(
        "getByBlockHeader called for block {}: returning spec with preExecutionProcessor={}",
        blockHeader.getNumber(),
        spec == null ? "NULL_SPEC" : (spec.getPreExecutionProcessor() == null ? "NULL" : spec.getPreExecutionProcessor().getClass().getSimpleName()));
    // Always return the single spec, regardless of block number or timestamp
    return spec;
  }

  @Override
  public Optional<ScheduledProtocolSpec> getNextProtocolSpec(final long currentTime) {
    // No future forks in a single-spec schedule
    return Optional.empty();
  }

  @Override
  public Optional<ScheduledProtocolSpec> getLatestProtocolSpec() {
    // Not needed for single-block processing
    return Optional.empty();
  }

  @Override
  public Optional<BigInteger> getChainId() {
    return chainId;
  }

  @Override
  public String listMilestones() {
    // No milestones to list
    return "";
  }

  @Override
  public void putBlockNumberMilestone(final long blockNumber, final ProtocolSpec protocolSpec) {
    // No-op - we already have our single spec
  }

  @Override
  public void putTimestampMilestone(final long timestamp, final ProtocolSpec protocolSpec) {
    // No-op - we already have our single spec
  }

  @Override
  public boolean isOnMilestoneBoundary(final BlockHeader blockHeader) {
    // Not relevant for single-block processing
    return false;
  }

  @Override
  public boolean anyMatch(final Predicate<ScheduledProtocolSpec> predicate) {
    // Not used in single-block processing
    return false;
  }

  @Override
  public void setPermissionTransactionFilter(
      final PermissionTransactionFilter permissionTransactionFilter) {
    // No-op for single-block processing
  }

  @Override
  public void setAdditionalValidationRules(
      final List<TransactionValidationRule> additionalValidationRules) {
    // No-op for single-block processing
  }
}
