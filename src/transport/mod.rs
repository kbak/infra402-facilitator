//! Ordered-failover transport with circuit breaker.
//!
//! Tries transports in strict insertion order. Falls through on:
//! - Transport errors (timeout, DNS, connection) — increments circuit breaker
//! - Retryable JSON-RPC errors (429, -32005, etc.) — does NOT increment circuit breaker
//!
//! When all transports are exhausted by retryable JSON-RPC errors, returns the last
//! `ErrorPayload` as `TransportError::ErrorResp` so `RetryBackoffLayer` can retry
//! with `backoff_hint()`.
//!
//! Circuit breaker: after `threshold` consecutive transport failures, skips the
//! transport for `cooldown` duration. If ALL transports are in cooldown, force-probes
//! the first transport rather than returning an immediate hard failure.
//! Set `threshold=0` to disable circuit breaker.

use alloy_json_rpc::{ErrorPayload, RequestPacket, ResponsePacket, RpcError};
use alloy::transports::{TransportError, TransportErrorKind, TransportFut};
use serde_json::value::RawValue;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tower::Service;

/// Check if any error in the response packet is retryable (rate-limit, etc.).
fn is_retryable_response(resp: &ResponsePacket) -> bool {
    resp.iter_errors()
        .any(|err: &ErrorPayload<Box<RawValue>>| err.is_retry_err())
}

/// Extract the first retryable error payload for propagation to `RetryBackoffLayer`.
fn first_retryable_error(resp: &ResponsePacket) -> Option<ErrorPayload<Box<RawValue>>> {
    resp.iter_errors()
        .find(|err: &&ErrorPayload<Box<RawValue>>| err.is_retry_err())
        .cloned()
}

/// Per-transport circuit breaker state.
///
/// Tracks consecutive transport-level failures (NOT retryable JSON-RPC errors).
/// After `threshold` consecutive failures, the transport is skipped for `cooldown`.
struct TransportState {
    consecutive_failures: AtomicU32,
    circuit_opened_at: RwLock<Option<Instant>>,
}

impl TransportState {
    fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            circuit_opened_at: RwLock::new(None),
        }
    }

    /// Returns true if this transport should be attempted.
    ///
    /// - `threshold=0` disables circuit breaker (always available).
    /// - Otherwise, available if failures < threshold or cooldown has elapsed.
    fn is_available(&self, threshold: u32, cooldown: Duration) -> bool {
        if threshold == 0 {
            return true;
        }
        if self.consecutive_failures.load(Ordering::Relaxed) < threshold {
            return true;
        }
        match *self.circuit_opened_at.read().unwrap() {
            Some(opened_at) => opened_at.elapsed() >= cooldown,
            None => true,
        }
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.circuit_opened_at.write().unwrap() = None;
    }

    /// Record a transport-level failure. Opens circuit after `threshold` consecutive failures.
    fn record_failure(&self, threshold: u32) {
        if threshold == 0 {
            return;
        }
        let prev = self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        if prev + 1 >= threshold {
            *self.circuit_opened_at.write().unwrap() = Some(Instant::now());
        }
    }
}

/// Ordered-failover transport service.
///
/// Wraps multiple transports and tries them in strict insertion order.
/// Implements [`tower::Service`] so it can be used with [`alloy::rpc::client::RpcClient`].
#[derive(Clone)]
pub struct OrderedFallbackService<S> {
    transports: Vec<S>,
    states: Arc<Vec<TransportState>>,
    failure_threshold: u32,
    cooldown: Duration,
}

impl<S: Clone> OrderedFallbackService<S> {
    /// Create a new ordered fallback service.
    ///
    /// - `failure_threshold`: consecutive transport failures before skipping. 0 = disabled.
    /// - `cooldown`: how long to skip a failing transport before re-probing.
    pub fn new(
        transports: Vec<S>,
        failure_threshold: u32,
        cooldown: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if transports.is_empty() {
            return Err("at least one transport required".into());
        }
        let states = (0..transports.len())
            .map(|_| TransportState::new())
            .collect();
        Ok(Self {
            transports,
            states: Arc::new(states),
            failure_threshold,
            cooldown,
        })
    }
}

impl<S> Service<RequestPacket> for OrderedFallbackService<S>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + Sync
        + Clone
        + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let transports = self.transports.clone();
        let states = Arc::clone(&self.states);
        let threshold = self.failure_threshold;
        let cooldown = self.cooldown;

        Box::pin(async move {
            let mut last_error: Option<TransportError> = None;
            let mut last_retryable_payload: Option<ErrorPayload<Box<RawValue>>> = None;
            let mut any_attempted = false;

            for (i, mut transport) in transports.iter().cloned().enumerate() {
                if !states[i].is_available(threshold, cooldown) {
                    tracing::debug!(transport = i, "circuit open, skipping");
                    continue;
                }

                any_attempted = true;

                match transport.call(req.clone()).await {
                    Ok(resp) if is_retryable_response(&resp) => {
                        // Retryable JSON-RPC error (429, -32005, etc.)
                        // Fall through to next transport, do NOT trip circuit breaker
                        if let Some(payload) = first_retryable_error(&resp) {
                            last_retryable_payload = Some(payload);
                        }
                        tracing::warn!(transport = i, "retryable JSON-RPC error, trying next");
                    }
                    Ok(resp) => {
                        states[i].record_success();
                        return Ok(resp);
                    }
                    Err(e) => {
                        // Transport-level failure — trip circuit breaker
                        states[i].record_failure(threshold);
                        tracing::warn!(transport = i, error = %e, "transport error, trying next");
                        last_error = Some(e);
                    }
                }
            }

            // All transports in cooldown — force-probe first transport
            if !any_attempted {
                tracing::warn!("all transports in cooldown, force-probing transport #0");
                let mut transport = transports[0].clone();
                match transport.call(req).await {
                    Ok(resp) if is_retryable_response(&resp) => {
                        if let Some(payload) = first_retryable_error(&resp) {
                            last_retryable_payload = Some(payload);
                        }
                    }
                    Ok(resp) => {
                        states[0].record_success();
                        return Ok(resp);
                    }
                    Err(e) => {
                        states[0].record_failure(threshold);
                        last_error = Some(e);
                    }
                }
            }

            // Prefer retryable payload — enables RetryBackoffLayer retry + backoff_hint()
            Err(if let Some(payload) = last_retryable_payload {
                RpcError::ErrorResp(payload)
            } else if let Some(err) = last_error {
                err
            } else {
                TransportErrorKind::custom_str("all transports failed")
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_rpc::{Id, Response, ResponsePayload};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ── helpers ──────────────────────────────────────────────────────────

    /// Mock transport whose responses are pre-loaded in a queue.
    #[derive(Clone)]
    struct MockTransport {
        responses: Arc<Mutex<VecDeque<Result<ResponsePacket, TransportError>>>>,
        call_count: Arc<AtomicU32>,
    }

    impl MockTransport {
        fn new(responses: Vec<Result<ResponsePacket, TransportError>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                call_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl Service<RequestPacket> for MockTransport {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: RequestPacket) -> Self::Future {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let next = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("MockTransport: no more queued responses");
            Box::pin(async move { next })
        }
    }

    fn make_request() -> RequestPacket {
        use alloy_json_rpc::Request;
        let req = Request::new("eth_blockNumber", Id::Number(1), ());
        RequestPacket::Single(req.serialize().expect("serialize request"))
    }

    fn ok_response() -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(1),
            payload: ResponsePayload::Success(
                serde_json::value::to_raw_value(&serde_json::json!("0x1")).unwrap(),
            ),
        })
    }

    fn rate_limit_response() -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(1),
            payload: ResponsePayload::Failure(ErrorPayload {
                code: 429,
                message: "too many requests".into(),
                data: None,
            }),
        })
    }

    fn transport_error() -> TransportError {
        TransportErrorKind::custom_str("connection refused")
    }

    // ── tests ───────────────────────────────────────────────────────────

    #[test]
    fn empty_transports_rejected() {
        let result = OrderedFallbackService::<MockTransport>::new(vec![], 3, Duration::from_secs(30));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn single_transport_success() {
        let t = MockTransport::new(vec![Ok(ok_response())]);
        let mut svc =
            OrderedFallbackService::new(vec![t.clone()], 3, Duration::from_secs(30)).unwrap();
        let result = svc.call(make_request()).await;
        assert!(result.is_ok());
        assert_eq!(t.calls(), 1);
    }

    #[tokio::test]
    async fn failover_to_second_on_transport_error() {
        let t1 = MockTransport::new(vec![Err(transport_error())]);
        let t2 = MockTransport::new(vec![Ok(ok_response())]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        let result = svc.call(make_request()).await;
        assert!(result.is_ok());
        assert_eq!(t1.calls(), 1);
        assert_eq!(t2.calls(), 1);
    }

    #[tokio::test]
    async fn failover_on_retryable_429() {
        let t1 = MockTransport::new(vec![Ok(rate_limit_response())]);
        let t2 = MockTransport::new(vec![Ok(ok_response())]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        let result = svc.call(make_request()).await;
        assert!(result.is_ok());
        assert_eq!(t1.calls(), 1);
        assert_eq!(t2.calls(), 1);
    }

    #[tokio::test]
    async fn all_retryable_returns_error_resp() {
        let t1 = MockTransport::new(vec![Ok(rate_limit_response())]);
        let t2 = MockTransport::new(vec![Ok(rate_limit_response())]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        let result = svc.call(make_request()).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Should be ErrorResp so RetryBackoffLayer can use backoff_hint()
        assert!(
            matches!(err, TransportError::ErrorResp(_)),
            "expected ErrorResp, got {err:?}"
        );
    }

    #[tokio::test]
    async fn retryable_preferred_over_transport_error() {
        // t1: transport error, t2: retryable 429
        // Result should be ErrorResp (retryable), not the transport error
        let t1 = MockTransport::new(vec![Err(transport_error())]);
        let t2 = MockTransport::new(vec![Ok(rate_limit_response())]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        let result = svc.call(make_request()).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), TransportError::ErrorResp(_)),
            "expected retryable ErrorResp to be preferred"
        );
    }

    #[tokio::test]
    async fn retryable_does_not_trip_circuit_breaker() {
        // Threshold=1 so a single transport error would trip it.
        // Send retryable 429 first, then a success — both to t1.
        // If 429 tripped the circuit breaker, the second call would skip t1.
        let t1 = MockTransport::new(vec![Ok(rate_limit_response()), Ok(ok_response())]);
        let mut svc =
            OrderedFallbackService::new(vec![t1.clone()], 1, Duration::from_secs(30)).unwrap();

        // First call — 429 (retryable), no second transport to fall through to
        let r1 = svc.call(make_request()).await;
        assert!(r1.is_err()); // all transports exhausted

        // Second call — should still try t1 (circuit NOT tripped by 429)
        let r2 = svc.call(make_request()).await;
        assert!(r2.is_ok());
        assert_eq!(t1.calls(), 2);
    }

    #[tokio::test]
    async fn circuit_breaker_trips_after_threshold() {
        // threshold=2, send 2 transport errors, then check circuit is open
        let t1 = MockTransport::new(vec![
            Err(transport_error()),
            Err(transport_error()),
            Ok(ok_response()), // force-probe response
        ]);
        let t2 = MockTransport::new(vec![
            Err(transport_error()),
            Err(transport_error()),
            Ok(ok_response()), // force-probe fallback
        ]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            2,
            Duration::from_secs(300), // long cooldown — stays open
        )
        .unwrap();

        // Call 1: t1 fails (1/2), t2 fails (1/2)
        let _ = svc.call(make_request()).await;
        // Call 2: t1 fails (2/2 → circuit opens), t2 fails (2/2 → circuit opens)
        let _ = svc.call(make_request()).await;

        // Call 3: both circuits open → force-probe t1
        let r3 = svc.call(make_request()).await;
        assert!(r3.is_ok());
        // t1 was called 3 times (2 normal + 1 force-probe), t2 only 2 times (skipped on call 3)
        assert_eq!(t1.calls(), 3);
        assert_eq!(t2.calls(), 2);
    }

    #[tokio::test]
    async fn circuit_breaker_disabled_when_threshold_zero() {
        // threshold=0 → circuit breaker disabled, always attempt
        let t1 = MockTransport::new(vec![
            Err(transport_error()),
            Err(transport_error()),
            Err(transport_error()),
            Ok(ok_response()),
        ]);
        let mut svc =
            OrderedFallbackService::new(vec![t1.clone()], 0, Duration::from_secs(30)).unwrap();

        // 3 failures should NOT trip the circuit
        let _ = svc.call(make_request()).await;
        let _ = svc.call(make_request()).await;
        let _ = svc.call(make_request()).await;
        // 4th call should still reach t1
        let r = svc.call(make_request()).await;
        assert!(r.is_ok());
        assert_eq!(t1.calls(), 4);
    }

    #[tokio::test]
    async fn success_resets_circuit_breaker() {
        // threshold=2, accumulate 1 failure, then succeed, then 1 more failure
        // The success should reset the counter so the second failure doesn't trip it
        let t1 = MockTransport::new(vec![
            Err(transport_error()), // failure #1
            Ok(ok_response()),      // success — resets counter
            Err(transport_error()), // failure #1 again (not #2)
            Ok(ok_response()),      // still available
        ]);
        let mut svc =
            OrderedFallbackService::new(vec![t1.clone()], 2, Duration::from_secs(300)).unwrap();

        let _ = svc.call(make_request()).await; // fail
        let _ = svc.call(make_request()).await; // success, resets
        let _ = svc.call(make_request()).await; // fail (count=1, not 2)
        let r = svc.call(make_request()).await; // should still try t1
        assert!(r.is_ok());
        assert_eq!(t1.calls(), 4);
    }

    #[tokio::test]
    async fn strict_order_primary_always_tried_first() {
        // When primary is healthy, secondary is never called
        let t1 = MockTransport::new(vec![Ok(ok_response()), Ok(ok_response())]);
        let t2 = MockTransport::new(vec![]);
        let mut svc = OrderedFallbackService::new(
            vec![t1.clone(), t2.clone()],
            3,
            Duration::from_secs(30),
        )
        .unwrap();

        let _ = svc.call(make_request()).await;
        let _ = svc.call(make_request()).await;
        assert_eq!(t1.calls(), 2);
        assert_eq!(t2.calls(), 0);
    }
}
