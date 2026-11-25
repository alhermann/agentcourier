//! End-to-end checks through the CLI against a real node, each with its own home folder and ports.
use serde_json::Value;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Node(&'static str);

/// The tests run in here and use relative home folders: with an absolute path, a long hostname in the socket's file
/// name exceeds the length limit of Unix socket paths (seen on macOS CI runners).
const DIR: &str = env!("CARGO_TARGET_TMPDIR");

impl Node {
    fn start(tag: &'static str) -> Node {
        let home = Path::new(DIR).join(tag);
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        // Both listeners stay open until both ports are known, so the two ports differ.
        let (a, b) = (TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap());
        let (listen, ipc) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
        drop((a, b));
        std::fs::write(home.join("config.toml"), format!("listen = \"127.0.0.1:{listen}\"\nipc_port = {ipc}\nnotify = false\n")).unwrap();
        let n = Node(tag);
        n.json(&["status"]);
        n
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agentcourier"));
        c.args(args).current_dir(DIR).env("AGENTCOURIER_HOME", self.0).env_remove("AGENTCOURIER_NAME").stdin(Stdio::null());
        c
    }

    fn json(&self, args: &[&str]) -> Value {
        let out = self.cmd(args).output().unwrap();
        assert!(out.status.success(), "agentcourier {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn spawn(&self, args: &[&str]) -> Child {
        self.cmd(args).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap()
    }

    /// Waits until the node's registered sessions are exactly `names`.
    fn wait_for_agents(&self, names: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let st = self.json(&["status"]);
            let mut now: Vec<String> = st["local_agents"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
            now.sort();
            if now == names {
                return;
            }
            assert!(Instant::now() < deadline, "local agents stayed {now:?}, expected {names:?}");
            sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.cmd(&["stop"]).output();
    }
}

/// Issue #201: a reader killed while it waits must not take a message that arrives after it is gone.
#[test]
fn killed_reader_leaves_held_message_for_next_reader() {
    let n = Node::start("held");
    let mut reader = n.spawn(&["recv", "--as", "desk", "--wait", "3"]);
    n.wait_for_agents(&["desk"]);
    reader.kill().unwrap();
    reader.wait().unwrap();
    n.wait_for_agents(&[]);
    let sent = n.json(&["send", "desk", "sent while nobody reads"]);
    assert_eq!(sent["status"], "held until the agent connects");
    // Past the killed reader's --wait, when its request used to empty the queue.
    sleep(Duration::from_secs(4));
    let got = n.json(&["recv", "--as", "desk"]);
    assert_eq!(got["messages"][0]["body"], "sent while nobody reads", "{got}");
}

/// A script that reads as NAME gets NAME's messages or an error, never a renamed inbox nobody writes to.
#[test]
fn recv_refuses_a_name_in_use() {
    let n = Node::start("busy");
    let mut holder = n.spawn(&["recv", "--as", "desk", "--wait", "30"]);
    n.wait_for_agents(&["desk"]);
    let out = n.cmd(&["recv", "--as", "desk"]).output().unwrap();
    let agents = n.json(&["status"])["local_agents"].clone();
    holder.kill().unwrap();
    holder.wait().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "recv as a taken name succeeded: {}", String::from_utf8_lossy(&out.stdout));
    assert!(err.contains("desk is in use"), "{err}");
    assert_eq!(agents, serde_json::json!(["desk"]));
}

/// A script calling recv in a loop gets its name back each time, also right after the previous run exited.
#[test]
fn back_to_back_recv_keeps_the_name() {
    let n = Node::start("loop");
    for i in 0..40 {
        let got = n.json(&["recv", "--as", "desk"]);
        assert_eq!(got["messages"], serde_json::json!([]), "run {i}");
    }
}

/// The node's own sender name cannot be read as; recv says so instead of claiming the name is in use.
#[test]
fn recv_refuses_the_reserved_name() {
    let n = Node::start("rsvd");
    let out = n.cmd(&["recv", "--as", "agentcourier"]).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "recv as the reserved name succeeded");
    assert!(err.contains("reserved"), "{err}");
    n.wait_for_agents(&[]);
}

/// A name whose previous reader is still being torn down is waited for briefly, not refused.
#[test]
fn recv_waits_briefly_for_a_name_being_released() {
    let n = Node::start("grace");
    let mut holder = n.spawn(&["recv", "--as", "desk", "--wait", "30"]);
    n.wait_for_agents(&["desk"]);
    let reader = n.cmd(&["recv", "--as", "desk"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    sleep(Duration::from_millis(200));
    holder.kill().unwrap();
    holder.wait().unwrap();
    let out = reader.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}
