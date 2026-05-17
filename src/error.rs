use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoTraceError {
    #[error("Sanitization error: {0}")]
    Sanitization(String),

    #[error("Input too large: {size} bytes (max: {max})")]
    InputTooLarge { size: usize, max: usize },

    #[error("Null bytes detected in string input")]
    NullBytesInString,

    #[error("Path traversal detected: {0}")]
    PathTraversal(String),

    #[error("Symlink detected pointing outside allowed directory")]
    SymlinkEscape,

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Compression bomb detected: expansion ratio {ratio}:1 exceeds limit {limit}:1")]
    CompressionBomb { ratio: f64, limit: f64 },

    #[error("Recursion depth exceeded: max {max}")]
    RecursionDepthExceeded { max: usize },

    #[error("Recursion timeout exceeded: {timeout}s")]
    RecursionTimeout { timeout: u64 },

    #[error("Cycle detected in recursive analysis")]
    CycleDetected,

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("AI provider error: {0}")]
    AiProvider(String),

    #[error("AI hallucination detected in field '{field}': '{value}' not in detection result")]
    AiHallucination { field: String, value: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CryptoTraceError>;
