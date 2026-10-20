//! Native subprocess runner for the 1Password CLI.
//!
//! * The program is executed directly with an argument vector. No shell is
//!   involved, so metacharacters in vault/item names are passed verbatim.
//! * stdin is closed; Keymesh never collects or forwards 1Password
//!   credentials. Authentication comes from the user's existing `op` session
//!   (desktop-app integration or `OP_SESSION_*` in the inherited environment).
//! * stdout/stderr are captured in memory (zeroized on drop), bounded in size,
//!   and never logged. A timeout kills the child.

use super::op::{OpRunner, RunError, RunOutput};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub struct ProcessOpRunner {
    pub program: PathBuf,
    pub timeout: Duration,
}

impl ProcessOpRunner {
    /// Uses `op` from `PATH`.
    pub fn new() -> Self {
        Self {
            program: PathBuf::from("op"),
            timeout: DEFAULT_TIMEOUT,
        }
    }
    pub fn with_program(program: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            timeout,
        }
    }
}

impl Default for ProcessOpRunner {
    fn default() -> Self {
        Self::new()
    }
}

fn read_capped(mut r: impl Read) -> Result<Zeroizing<Vec<u8>>, RunError> {
    let mut buf = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = r.read(&mut chunk[..]).map_err(|_| RunError::Io)?;
        if n == 0 {
            return Ok(buf);
        }
        if buf.len() + n > MAX_OUTPUT_BYTES {
            // Keep draining so the child is not blocked, but discard.
            let mut sink = std::io::sink();
            let _ = std::io::copy(&mut r, &mut sink);
            return Err(RunError::OutputTooLarge);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

impl OpRunner for ProcessOpRunner {
    fn run(&self, args: &[String]) -> Result<RunOutput, RunError> {
        let mut child = Command::new(&self.program)
            .args(args)
            .env_remove("OP_DEBUG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => RunError::MissingOp,
                _ => RunError::Io,
            })?;
        let stdout = child.stdout.take().ok_or(RunError::Io)?;
        let stderr = child.stderr.take().ok_or(RunError::Io)?;
        let out_t = thread::spawn(move || read_capped(stdout));
        let err_t = thread::spawn(move || read_capped(stderr));

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Reader threads are detached rather than joined: a
                    // grandchild may still hold the pipes open.
                    drop((out_t, err_t));
                    return Err(RunError::Timeout);
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Io);
                }
            }
        };
        let stdout = out_t.join().map_err(|_| RunError::Io)??;
        let stderr = err_t.join().map_err(|_| RunError::Io)??;
        Ok(RunOutput {
            status: status.code(),
            stdout,
            stderr,
        })
    }
}
