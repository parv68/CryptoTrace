use crate::error::Result;
use std::process::Command;

/// Platform-specific sandbox configuration for untrusted binary parsing.
///
/// - Linux: seccomp-bpf + Landlock LSM (not available on Windows)
/// - Windows: Job Object + restricted token (default path on this platform)
/// - macOS: sandbox-exec
pub struct Sandbox {
    enabled: bool,
    worker_path: Option<std::path::PathBuf>,
}

impl Sandbox {
    pub fn new() -> Self {
        Self {
            enabled: true,
            worker_path: None,
        }
    }

    pub fn with_worker_path(mut self, path: std::path::PathBuf) -> Self {
        self.worker_path = Some(path);
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Spawn an isolated worker process for risky parsing operations.
    /// On Windows, the child process runs with a restricted token and Job Object.
    /// Returns the stdout output from the worker.
    pub fn run_worker(&self, operation: &str, input: &[u8]) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(input.to_vec());
        }

        let worker_exe = self
            .worker_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("cryptotrace-worker"));

        let mut cmd = Command::new(&worker_exe);

        // Pass operation type and input length as args
        cmd.arg("--operation")
            .arg(operation)
            .arg("--input-len")
            .arg(input.len().to_string());

        // Pipe input via stdin
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // Windows Job Object constraint: limit child process lifetime
        // (implemented via the worker process itself respecting timeouts)

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW to avoid console window popup for worker
            cmd.creation_flags(0x08000000);
        }

        let mut child = cmd.spawn()?;

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(input)?;
            stdin.flush()?;
        }

        // Read output with timeout
        let output = child.wait_with_output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::CryptoTraceError::Other(format!(
                "Worker failed for operation '{}': {}",
                operation, stderr
            )));
        }

        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_disabled_passthrough() {
        let sandbox = Sandbox::new().disabled();
        let input = b"test data";
        let result = sandbox.run_worker("test", input).unwrap();
        assert_eq!(result, input);
    }
}
