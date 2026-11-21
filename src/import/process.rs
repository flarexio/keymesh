//! Native subprocess runner for the 1Password CLI.
//!
//! * The program is executed directly with an argument vector. No shell is
//!   involved, so metacharacters in vault/item names are passed verbatim.
//! * stdin is closed; Keymesh never collects or forwards 1Password
//!   credentials. Authentication comes from the user's existing `op` session
//!   (desktop-app integration or `OP_SESSION_*` in the inherited environment).
//! * stdout/stderr are captured in memory (zeroized on drop), bounded in size,
//!   and never logged.
//! * One deadline covers the whole run including output collection. On
//!   timeout the child's entire process group is killed (Unix), so
//!   descendants holding the pipes cannot hang the import. A descendant that
//!   detaches into its own session/group is outside this cleanup.

use super::op::{OpRunner, RunError, RunOutput};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
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

/// Kill the child and every process in its group. The child is spawned as
/// the leader of a new process group, so this reaches descendants that are
/// still holding the output pipes (unless they deliberately left the group).
fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        // The child is a group leader (process_group(0)), so its pid is the
        // pgid. POSIX does not reuse a pid while a group with that id exists,
        // so this cannot signal unrelated processes.
        if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
            // SAFETY: kill(2) has no memory-safety preconditions.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

enum Stream {
    Out,
    Err,
}

impl OpRunner for ProcessOpRunner {
    /// The timeout is end-to-end: it covers the child running *and* the
    /// collection of its output. Reader threads report over a channel; if they
    /// are still blocked at the deadline (e.g. a descendant holds the pipes
    /// open), the whole process group is killed and the threads are detached.
    fn run(&self, args: &[String]) -> Result<RunOutput, RunError> {
        let deadline = Instant::now() + self.timeout;
        let mut cmd = Command::new(&self.program);
        cmd.args(args)
            .env_remove("OP_DEBUG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let mut child = cmd.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => RunError::MissingOp,
            _ => RunError::Io,
        })?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            kill_tree(&mut child);
            return Err(RunError::Io);
        };
        let (tx, rx) = mpsc::channel();
        let tx2 = tx.clone();
        thread::spawn(move || {
            let _ = tx.send((Stream::Out, read_capped(stdout)));
        });
        thread::spawn(move || {
            let _ = tx2.send((Stream::Err, read_capped(stderr)));
        });

        let mut out = None;
        let mut err = None;
        while out.is_none() || err.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(remaining) {
                Ok((Stream::Out, Ok(b))) => out = Some(b),
                Ok((Stream::Err, Ok(b))) => err = Some(b),
                Ok((_, Err(e))) => {
                    kill_tree(&mut child);
                    return Err(e);
                }
                Err(RecvTimeoutError::Timeout) => {
                    kill_tree(&mut child);
                    return Err(RunError::Timeout);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    kill_tree(&mut child);
                    return Err(RunError::Io);
                }
            }
        }

        // Both pipes are closed; wait for exit within the same deadline.
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    kill_tree(&mut child);
                    return Err(RunError::Timeout);
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    kill_tree(&mut child);
                    return Err(RunError::Io);
                }
            }
        };
        Ok(RunOutput {
            status: status.code(),
            stdout: out.unwrap_or_default(),
            stderr: err.unwrap_or_default(),
        })
    }
}
