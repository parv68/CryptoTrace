/// AI provider abstraction. Placeholder for Phase 4 implementation.
/// All providers must be async.
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_airgap_safe(&self) -> bool;
}
