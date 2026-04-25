//! Developer-facing SDK primitives.
//! The simple mental model: compute -> verify -> cache -> retrieve with guarantees.

use crate::archive::ComputationFingerprint;
use crate::cache_api::CacheReceipt;
use crate::read_contract::CacheeReadResponse;

/// The three operations a developer needs to understand.
/// Everything else is implementation detail.
pub trait Cachee {
    /// Compute a result, verify it, and cache it in one call.
    /// This is the primary entry point for most use cases.
    ///
    /// ```ignore
    /// let receipt = cachee.compute_and_cache(
    ///     "pricing:AAPL:2026-04-23",
    ///     &|| { expensive_pricing_calculation() },
    ///     fingerprint,
    /// )?;
    /// ```
    fn compute_and_cache(
        &self,
        key: &str,
        compute_fn: &dyn Fn() -> Vec<u8>,
        fingerprint: ComputationFingerprint,
    ) -> Result<CacheReceipt, String>;

    /// Retrieve a result with full trust guarantees.
    /// Returns None if not cached. Never returns unverified data in safe mode.
    ///
    /// ```ignore
    /// if let Some(result) = cachee.get_verified("pricing:AAPL:2026-04-23")? {
    ///     println!("Trust score: {}", result.verification);
    ///     println!("Computation: {}", result.fingerprint.version.engine);
    ///     use_result(&result.value);
    /// }
    /// ```
    fn get_verified(&self, key: &str) -> Result<Option<CacheeReadResponse>, String>;

    /// Check if a cached result exists and is still valid.
    /// Does not return the value -- just the trust status.
    fn is_valid(&self, key: &str) -> Result<bool, String>;
}
