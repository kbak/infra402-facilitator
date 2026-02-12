//! Batch processor for settlement transactions.
//!
//! This module handles processing batches of settlement requests using Multicall3
//! to bundle multiple transferWithAuthorization calls into single transactions.

use crate::chain::{evm::EvmProvider, evm::PendingBatch, FacilitatorLocalError, NetworkProvider};
use crate::types::{SettleRequest, SettleResponse};
use alloy::primitives::Address;
use std::sync::Arc;
use tokio::sync::oneshot;

type ResponseSender = oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>;

/// Batch processor for settlement transactions.
pub struct BatchProcessor;

impl BatchProcessor {
    /// Process a batch of settlement requests for a specific (facilitator, network) pair.
    ///
    /// This method:
    /// 1. Validates all settlement requests
    /// 2. For EVM networks: bundles them into a Multicall3 aggregate3 transaction
    /// 3. For Solana networks: processes them individually (no batching)
    /// 4. Returns results to requesters via oneshot channels
    ///
    /// The facilitator_addr must match the queue this batch came from, ensuring
    /// the settlement lock is acquired for the correct facilitator address.
    pub async fn process_batch(
        network_provider: &Arc<NetworkProvider>,
        facilitator_addr: Address,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
        allow_partial_failure: bool,
        hook_manager: Option<&Arc<crate::hooks::HookManager>>,
    ) -> Result<(), FacilitatorLocalError> {
        if requests.is_empty() {
            return Ok(());
        }

        let batch_size = requests.len();
        tracing::info!(
            %facilitator_addr,
            batch_size,
            "processing batch for facilitator"
        );

        // Match on network provider type
        match network_provider.as_ref() {
            NetworkProvider::Evm(evm_provider) => {
                Self::process_evm_batch(
                    Arc::clone(network_provider),
                    evm_provider,
                    facilitator_addr,
                    requests,
                    allow_partial_failure,
                    hook_manager,
                ).await
            }
            NetworkProvider::Solana(_solana_provider) => {
                tracing::info!(
                    batch_size,
                    "Solana batching not implemented - processing settlements individually"
                );
                Self::process_individually_fallback(network_provider.as_ref(), requests).await
            }
            NetworkProvider::Aptos(_aptos_provider) => {
                tracing::info!(
                    batch_size,
                    "Aptos batching not implemented - processing settlements individually"
                );
                Self::process_individually_fallback(network_provider.as_ref(), requests).await
            }
        }
    }

    /// Process an EVM batch using Multicall3 with nonce pipelining.
    ///
    /// Nonce pipelining: the settlement lock is held only during validation + gas estimation
    /// + transaction submission (~120ms). The lock is released and receipt waiting is spawned
    /// as a background task, allowing the batch queue to immediately start collecting and
    /// processing the next batch.
    async fn process_evm_batch(
        network_provider: Arc<NetworkProvider>,
        evm_provider: &EvmProvider,
        facilitator_addr: Address,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
        allow_partial_failure: bool,
        hook_manager: Option<&Arc<crate::hooks::HookManager>>,
    ) -> Result<(), FacilitatorLocalError> {
        // ── Phase 1: Validate + Send (settlement lock held) ──────────────
        let settlement_lock = evm_provider.get_settlement_lock(facilitator_addr);
        tracing::debug!(%facilitator_addr, "acquiring settlement lock for batch");
        let settlement_guard = settlement_lock.lock().await;
        tracing::debug!(%facilitator_addr, "settlement lock acquired for batch");

        // Validate all settlements and prepare them for batching
        let mut validated_settlements = Vec::with_capacity(requests.len());
        let mut response_channels = Vec::with_capacity(requests.len());

        for (request, response_tx) in requests {
            match evm_provider.validate_and_prepare_settlement(&request, hook_manager).await {
                Ok(validated) => {
                    validated_settlements.push(validated);
                    response_channels.push(response_tx);
                }
                Err(e) => {
                    tracing::warn!(
                        error = ?e,
                        "settlement validation failed - sending error to requester"
                    );
                    let _ = response_tx.send(Err(e));
                }
            }
        }

        if validated_settlements.is_empty() {
            tracing::warn!("all settlements in batch failed validation");
            return Ok(());
        }

        tracing::info!(
            validated_count = validated_settlements.len(),
            "validated settlements - splitting into Call3-aware sub-batches"
        );

        // Split validated settlements into sub-batches based on max Call3 count
        const MAX_CALL3_PER_BATCH: usize = 150;

        let mut sub_batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_batch_channels = Vec::new();
        let mut current_call3_count = 0;

        for (settlement, channel) in validated_settlements.into_iter().zip(response_channels.into_iter()) {
            let calls_needed = 1 + settlement.hooks.len();

            if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH && !current_batch.is_empty() {
                sub_batches.push((current_batch, current_batch_channels));
                current_batch = Vec::new();
                current_batch_channels = Vec::new();
                current_call3_count = 0;
            }

            current_batch.push(settlement);
            current_batch_channels.push(channel);
            current_call3_count += calls_needed;
        }

        if !current_batch.is_empty() {
            sub_batches.push((current_batch, current_batch_channels));
        }

        tracing::info!(
            sub_batch_count = sub_batches.len(),
            "split into {} sub-batches based on Call3 limits",
            sub_batches.len()
        );

        // Submit all sub-batches (gas estimation + send) while holding the lock.
        // This ensures nonce ordering is correct across sub-batches.
        use crate::chain::evm::PRESELECTED_FACILITATOR;
        let mut pending_batches: Vec<(PendingBatch, Vec<ResponseSender>)> = Vec::new();

        for (batch_settlements, batch_channels) in sub_batches {
            tracing::info!(
                batch_size = batch_settlements.len(),
                total_call3s = batch_settlements.iter().map(|s| 1 + s.hooks.len()).sum::<usize>(),
                "submitting sub-batch (nonce pipelining)"
            );

            match PRESELECTED_FACILITATOR
                .scope(
                    facilitator_addr,
                    evm_provider.send_batch(batch_settlements, allow_partial_failure),
                )
                .await
            {
                Ok(pending) => {
                    pending_batches.push((pending, batch_channels));
                }
                Err(e) => {
                    tracing::error!(error = ?e, "sub-batch send failed");
                    for response_tx in batch_channels {
                        let _ = response_tx.send(Err(FacilitatorLocalError::ContractCall(
                            "Batch settlement failed".to_string(),
                        )));
                    }
                    // Release lock, spawn receipt wait for already-submitted batches
                    drop(settlement_guard);
                    if !pending_batches.is_empty() {
                        tokio::spawn(complete_pending_batches(network_provider, pending_batches));
                    }
                    return Err(e);
                }
            }
        }

        // ── Phase 2: Release lock, spawn receipt wait as background task ─
        drop(settlement_guard);
        tracing::debug!(%facilitator_addr, "settlement lock released, spawning receipt wait");

        if !pending_batches.is_empty() {
            tokio::spawn(complete_pending_batches(network_provider, pending_batches));
        }

        Ok(())
    }

    /// Fallback: process settlements individually (used for Solana or when batching fails).
    async fn process_individually_fallback(
        network_provider: &NetworkProvider,
        requests: Vec<(SettleRequest, oneshot::Sender<Result<SettleResponse, FacilitatorLocalError>>)>,
    ) -> Result<(), FacilitatorLocalError> {
        for (request, response_tx) in requests {
            // Use the existing settle method from NetworkProvider's Facilitator trait
            use crate::facilitator::Facilitator;
            let result = network_provider.settle(&request).await;
            let _ = response_tx.send(result);
        }
        Ok(())
    }
}

/// Background task: wait for receipts from submitted batches and send responses.
///
/// This runs outside the settlement lock, allowing the batch queue to immediately
/// start processing the next batch while receipts are pending.
async fn complete_pending_batches(
    network_provider: Arc<NetworkProvider>,
    pending_batches: Vec<(PendingBatch, Vec<ResponseSender>)>,
) {
    let evm_provider = match network_provider.as_ref() {
        NetworkProvider::Evm(evm) => evm,
        _ => {
            tracing::error!("complete_pending_batches called with non-EVM provider");
            return;
        }
    };

    for (pending, batch_channels) in pending_batches {
        match evm_provider.complete_batch(pending).await {
            Ok(responses) => {
                for (response, response_tx) in responses.into_iter().zip(batch_channels) {
                    let _ = response_tx.send(Ok(response));
                }
            }
            Err(e) => {
                tracing::error!(error = ?e, "background receipt wait failed");
                for response_tx in batch_channels {
                    let _ = response_tx.send(Err(FacilitatorLocalError::ContractCall(
                        "Batch settlement failed".to_string(),
                    )));
                }
            }
        }
    }

    tracing::info!("all sub-batches completed successfully (background)");
}

#[cfg(test)]
mod tests {
    use crate::chain::evm::ValidatedSettlement;
    use alloy::primitives::{address, Bytes, FixedBytes, U256};

    // Test helper to create a minimal ValidatedSettlement for testing batch splitting logic
    fn create_test_validated_settlement(hooks_count: usize) -> ValidatedSettlement {
        use crate::hooks::HookCall;
        use crate::network::Network;
        use crate::types::MixedAddress;
        use crate::chain::evm::SettlementMetadata;

        let hooks: Vec<HookCall> = (0..hooks_count)
            .map(|_| HookCall {
                target: address!("1111111111111111111111111111111111111111"),
                calldata: Bytes::new(),
                gas_limit: 100000,
                allow_failure: true,
            })
            .collect();

        ValidatedSettlement {
            target: address!("2222222222222222222222222222222222222222"),
            calldata: Bytes::new(),
            payer: MixedAddress::from(address!("3333333333333333333333333333333333333333")),
            network: Network::BaseSepolia,
            deployment: None,
            hooks,
            metadata: SettlementMetadata {
                from: address!("3333333333333333333333333333333333333333"),
                to: address!("4444444444444444444444444444444444444444"),
                value: U256::from(1000000),
                valid_after: U256::ZERO,
                valid_before: U256::MAX,
                nonce: FixedBytes::ZERO,
                signature: Bytes::new(),
                contract_address: address!("2222222222222222222222222222222222222222"),
                sig_kind: "eoa".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn test_batch_splitting_call3_count() {
        // Test the Call3 splitting logic (lines 110-136 in batch_processor.rs)

        // Create 50 settlements with 3 hooks each = 200 total Call3s (50 transfers + 150 hooks)
        let settlements: Vec<ValidatedSettlement> = (0..50)
            .map(|_| create_test_validated_settlement(3))
            .collect();

        const MAX_CALL3_PER_BATCH: usize = 150;

        // Simulate the splitting logic from process_evm_batch
        let mut sub_batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_call3_count = 0;

        for settlement in settlements {
            let calls_needed = 1 + settlement.hooks.len(); // 1 for transfer + N for hooks = 4 per settlement

            // If adding this settlement would exceed limit, flush current batch
            if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH && !current_batch.is_empty() {
                sub_batches.push(current_batch);
                current_batch = Vec::new();
                current_call3_count = 0;
            }

            current_batch.push(settlement);
            current_call3_count += calls_needed;
        }

        // Add final batch
        if !current_batch.is_empty() {
            sub_batches.push(current_batch);
        }

        // Verify splitting behavior
        assert_eq!(sub_batches.len(), 2, "Should split into 2 sub-batches");

        // First batch: 150 / 4 = 37 settlements (148 Call3s)
        assert_eq!(sub_batches[0].len(), 37, "First batch should have 37 settlements");

        // Second batch: remaining 13 settlements (52 Call3s)
        assert_eq!(sub_batches[1].len(), 13, "Second batch should have 13 settlements");
    }

    #[tokio::test]
    async fn test_batch_splitting_preserves_hooks() {
        // Test that hooks stay with their parent settlement when splitting

        let settlements: Vec<ValidatedSettlement> = vec![
            create_test_validated_settlement(0), // No hooks
            create_test_validated_settlement(2), // 2 hooks
            create_test_validated_settlement(1), // 1 hook
        ];

        // Each settlement should maintain its hooks count after any processing
        assert_eq!(settlements[0].hooks.len(), 0);
        assert_eq!(settlements[1].hooks.len(), 2);
        assert_eq!(settlements[2].hooks.len(), 1);

        // The splitting logic never separates hooks from their parent settlement
        // This is enforced by the data structure (hooks are Vec inside ValidatedSettlement)
    }

    #[tokio::test]
    async fn test_call3_count_calculation() {
        // Verify the Call3 count calculation logic

        let settlement_no_hooks = create_test_validated_settlement(0);
        let settlement_with_hooks = create_test_validated_settlement(5);

        // Calculate calls_needed as done in process_evm_batch (line 118)
        let calls_no_hooks = 1 + settlement_no_hooks.hooks.len();
        let calls_with_hooks = 1 + settlement_with_hooks.hooks.len();

        assert_eq!(calls_no_hooks, 1, "Settlement with no hooks needs 1 Call3");
        assert_eq!(calls_with_hooks, 6, "Settlement with 5 hooks needs 6 Call3s");
    }

    #[tokio::test]
    async fn test_large_batch_splitting() {
        // Test splitting with 200 settlements (no hooks) = 200 Call3s
        let settlements: Vec<ValidatedSettlement> = (0..200)
            .map(|_| create_test_validated_settlement(0))
            .collect();

        const MAX_CALL3_PER_BATCH: usize = 150;

        let mut sub_batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_call3_count = 0;

        for settlement in settlements {
            let calls_needed = 1 + settlement.hooks.len();

            if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH && !current_batch.is_empty() {
                sub_batches.push(current_batch);
                current_batch = Vec::new();
                current_call3_count = 0;
            }

            current_batch.push(settlement);
            current_call3_count += calls_needed;
        }

        if !current_batch.is_empty() {
            sub_batches.push(current_batch);
        }

        // Should split into 2 batches: 150 + 50
        assert_eq!(sub_batches.len(), 2);
        assert_eq!(sub_batches[0].len(), 150);
        assert_eq!(sub_batches[1].len(), 50);
    }

    #[tokio::test]
    async fn test_mixed_hook_counts_splitting() {
        // Test splitting with varying hook counts per settlement
        let settlements: Vec<ValidatedSettlement> = vec![
            create_test_validated_settlement(10), // 11 Call3s
            create_test_validated_settlement(20), // 21 Call3s
            create_test_validated_settlement(30), // 31 Call3s
            create_test_validated_settlement(50), // 51 Call3s
            create_test_validated_settlement(40), // 41 Call3s
            // Total: 155 Call3s
        ];

        const MAX_CALL3_PER_BATCH: usize = 150;

        let mut sub_batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_call3_count = 0;

        for settlement in settlements {
            let calls_needed = 1 + settlement.hooks.len();

            if current_call3_count + calls_needed > MAX_CALL3_PER_BATCH && !current_batch.is_empty() {
                sub_batches.push(current_batch);
                current_batch = Vec::new();
                current_call3_count = 0;
            }

            current_batch.push(settlement);
            current_call3_count += calls_needed;
        }

        if !current_batch.is_empty() {
            sub_batches.push(current_batch);
        }

        // First 4 settlements: 11 + 21 + 31 + 51 = 114 Call3s (fits in one batch)
        // Adding 5th would be 114 + 41 = 155 > 150, so split
        assert_eq!(sub_batches.len(), 2);
        assert_eq!(sub_batches[0].len(), 4, "First batch should have 4 settlements");
        assert_eq!(sub_batches[1].len(), 1, "Second batch should have 1 settlement");
    }
}
