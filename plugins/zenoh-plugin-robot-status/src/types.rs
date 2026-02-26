use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KeepaliveConfig {
    #[serde(default = "default_timeout_secs")]
    pub(crate) timeout_secs: u64,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Config {
    pub(crate) api_base_url: String,
    pub(crate) auth_token: String,
    pub(crate) project_id: String,
    #[serde(default)]
    pub(crate) keepalive: KeepaliveConfig,
}

fn default_timeout_secs() -> u64 {
    0
}

#[derive(Clone)]
pub(crate) struct SessionRecord {
    pub(crate) robot_id: String,
    pub(crate) last_keepalive: Instant,
    pub(crate) last_report_code: Option<u16>,
    pub(crate) last_report_error: Option<String>,
    pub(crate) connected_at_ms: u128,
}

#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) active_sessions: usize,
    pub(crate) report_ok: u64,
    pub(crate) report_err: u64,
    pub(crate) robot_id_missing: u64,
    pub(crate) keepalive_timeout: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RobotStatus {
    Online,
    Offline,
}

impl RobotStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            RobotStatus::Online => "ONLINE",
            RobotStatus::Offline => "OFFLINE",
        }
    }
}

pub(crate) struct ReportCommand {
    pub(crate) session_id: String,
    pub(crate) robot_id: String,
    pub(crate) status: RobotStatus,
}

pub(crate) fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
