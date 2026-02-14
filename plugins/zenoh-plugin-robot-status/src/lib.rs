use std::{
    any::Any,
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tracing::{debug, error, info, warn};
use zenoh::{
    internal::{
        bail,
        plugins::{RunningPluginTrait, ZenohPlugin},
        runtime::DynamicRuntime,
        zlock,
    },
    key_expr::KeyExpr,
    Result as ZResult,
};
use zenoh_plugin_trait::{plugin_long_version, plugin_version, Plugin, PluginControl};
use zenoh_transport::{
    multicast::TransportMulticast, unicast::TransportUnicast, TransportEventHandler,
    TransportMulticastEventHandler, TransportPeer, TransportPeerEventHandler,
};
use zenoh_util::ffi::JsonKeyValueMap;

#[cfg(feature = "dynamic_plugin")]
zenoh_plugin_trait::declare_plugin!(RobotStatusPlugin);

pub struct RobotStatusPlugin {}

impl ZenohPlugin for RobotStatusPlugin {}

impl Plugin for RobotStatusPlugin {
    type StartArgs = DynamicRuntime;
    type Instance = zenoh::internal::plugins::RunningPlugin;

    const DEFAULT_NAME: &'static str = "robot_status";
    const PLUGIN_VERSION: &'static str = plugin_version!();
    const PLUGIN_LONG_VERSION: &'static str = plugin_long_version!();

    fn start(name: &str, runtime: &Self::StartArgs) -> ZResult<Self::Instance> {
        zenoh::init_log_from_env_or("error");
        debug!("Robot status plugin {}", Self::PLUGIN_LONG_VERSION);

        let plugin_conf = runtime
            .get_config()
            .get_plugin_config(name)
            .map_err(|_| zenoh::internal::zerror!("Plugin `{}`: missing config", name))?;
        let config: Config = serde_json::from_value(plugin_conf)
            .map_err(|e| zenoh::internal::zerror!("Plugin `{}` config error: {}", name, e))?;

        let shared = Arc::new(SharedState::new(config.clone()));
        runtime.new_handler(Arc::new(ConnectionObserver::new(shared.clone())));

        spawn_background_workers(shared.clone());

        Ok(Box::new(RunningPlugin(Arc::new(Mutex::new(
            RunningPluginInner {
                name: name.to_string(),
                config,
                state: shared,
            },
        )))))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct KeepaliveConfig {
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    api_base_url: String,
    auth_token: String,
    project_id: String,
    #[serde(default)]
    keepalive: KeepaliveConfig,
}

fn default_timeout_secs() -> u64 {
    30
}

#[derive(Clone)]
struct SessionRecord {
    robot_id: String,
    last_keepalive: Instant,
    last_report_code: Option<u16>,
    last_report_error: Option<String>,
    connected_at_ms: u128,
}

#[derive(Default)]
struct Metrics {
    active_sessions: usize,
    report_ok: u64,
    report_err: u64,
    robot_id_missing: u64,
    keepalive_timeout: u64,
}

struct SharedState {
    config: Config,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    metrics: Arc<Mutex<Metrics>>,
    report_tx: mpsc::Sender<ReportCommand>,
    report_rx: Mutex<Option<mpsc::Receiver<ReportCommand>>>,
}

impl SharedState {
    fn new(config: Config) -> Self {
        let (report_tx, report_rx) = mpsc::channel(2048);
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Metrics::default())),
            report_tx,
            report_rx: Mutex::new(Some(report_rx)),
        }
    }

    fn on_connect(&self, session_id: String, robot_id: String) {
        let mut sessions = zlock!(self.sessions);
        let now = Instant::now();
        let connected_at_ms = now_epoch_ms();
        sessions.insert(
            session_id.clone(),
            SessionRecord {
                robot_id: robot_id.clone(),
                last_keepalive: now,
                last_report_code: None,
                last_report_error: None,
                connected_at_ms,
            },
        );
        zlock!(self.metrics).active_sessions = sessions.len();
        drop(sessions);
        self.enqueue_report(session_id, robot_id, RobotStatus::Online);
    }

    fn on_message(&self, session_id: &str) {
        if let Some(record) = zlock!(self.sessions).get_mut(session_id) {
            record.last_keepalive = Instant::now();
        }
    }

    fn on_disconnect(&self, session_id: &str, reason: &str) {
        let removed = zlock!(self.sessions).remove(session_id);
        zlock!(self.metrics).active_sessions = zlock!(self.sessions).len();
        if let Some(record) = removed {
            info!(
                session_id,
                robot_id = record.robot_id,
                reason,
                connected_at_ms = record.connected_at_ms,
                "session disconnected"
            );
            self.enqueue_report(session_id.to_owned(), record.robot_id, RobotStatus::Offline);
        }
    }

    fn enqueue_report(&self, session_id: String, robot_id: String, status: RobotStatus) {
        let command = ReportCommand {
            session_id,
            robot_id,
            status,
        };
        if let Err(e) = self.report_tx.try_send(command) {
            error!("report queue full, dropping event: {e}");
            zlock!(self.metrics).report_err += 1;
        }
    }

    fn update_report_result(&self, session_id: &str, code: Option<u16>, error: Option<String>) {
        if let Some(session) = zlock!(self.sessions).get_mut(session_id) {
            session.last_report_code = code;
            session.last_report_error = error;
        }
    }

    fn take_report_rx(&self) -> Option<mpsc::Receiver<ReportCommand>> {
        zlock!(self.report_rx).take()
    }
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Clone, Copy, Debug)]
enum RobotStatus {
    Online,
    Offline,
}

impl RobotStatus {
    fn as_str(&self) -> &'static str {
        match self {
            RobotStatus::Online => "ONLINE",
            RobotStatus::Offline => "OFFLINE",
        }
    }
}

struct ReportCommand {
    session_id: String,
    robot_id: String,
    status: RobotStatus,
}

fn spawn_background_workers(shared: Arc<SharedState>) {
    let report_shared = shared.clone();
    if let Some(mut rx) = report_shared.take_report_rx() {
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let result = send_patch_report(&report_shared.config, &cmd);
                match result {
                    Ok(code) if code == 200 => {
                        zlock!(report_shared.metrics).report_ok += 1;
                        report_shared.update_report_result(&cmd.session_id, Some(code), None);
                    }
                    Ok(code) => {
                        zlock!(report_shared.metrics).report_err += 1;
                        report_shared.update_report_result(
                            &cmd.session_id,
                            Some(code),
                            Some(format!("unexpected http status {code}")),
                        );
                        warn!(
                            session_id = cmd.session_id,
                            robot_id = cmd.robot_id,
                            code,
                            "robot status report failed"
                        );
                    }
                    Err(e) => {
                        zlock!(report_shared.metrics).report_err += 1;
                        report_shared.update_report_result(&cmd.session_id, None, Some(e.clone()));
                        error!(
                            session_id = cmd.session_id,
                            robot_id = cmd.robot_id,
                            error = e,
                            "robot status report failed"
                        );
                    }
                }
            }
        });
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let timeout = Duration::from_secs(shared.config.keepalive.timeout_secs);
            let stale_ids: Vec<String> = {
                let sessions = zlock!(shared.sessions);
                sessions
                    .iter()
                    .filter(|(_, rec)| rec.last_keepalive.elapsed() >= timeout)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            if !stale_ids.is_empty() {
                zlock!(shared.metrics).keepalive_timeout += stale_ids.len() as u64;
                for session_id in stale_ids {
                    shared.on_disconnect(&session_id, "keepalive_timeout");
                }
            }
        }
    });
}

fn send_patch_report(config: &Config, cmd: &ReportCommand) -> Result<u16, String> {
    let url = format!(
        "{}/v1/{}/robots/{}/status?status={}",
        config.api_base_url.trim_end_matches('/'),
        config.project_id,
        cmd.robot_id,
        cmd.status.as_str()
    );
    let response = ureq::patch(&url)
        .set("X-Auth-Token", &config.auth_token)
        .call();

    match response {
        Ok(resp) => Ok(resp.status()),
        Err(ureq::Error::Status(code, _)) => Ok(code),
        Err(e) => Err(e.to_string()),
    }
}

struct ConnectionObserver {
    shared: Arc<SharedState>,
}

impl ConnectionObserver {
    fn new(shared: Arc<SharedState>) -> Self {
        Self { shared }
    }

    fn resolve_robot_id(peer: &TransportPeer) -> Option<String> {
        peer.links
            .iter()
            .find_map(|link| {
                link.auth_identifier
                    .get_cert_common_name()
                    .map(str::to_string)
            })
            .or_else(|| Some(peer.zid.to_string()))
    }
}

impl TransportEventHandler for ConnectionObserver {
    fn new_unicast(
        &self,
        peer: TransportPeer,
        _transport: TransportUnicast,
    ) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        if peer.whatami != zenoh_protocol::core::WhatAmI::Client {
            return Ok(Arc::new(NoopPeerHandler));
        }

        let session_id = peer.zid.to_string();
        match Self::resolve_robot_id(&peer) {
            Some(robot_id) => {
                self.shared.on_connect(session_id.clone(), robot_id.clone());
                Ok(Arc::new(SessionPeerHandler {
                    shared: self.shared.clone(),
                    session_id,
                }))
            }
            None => {
                self.shared.metrics.lock().unwrap().robot_id_missing += 1;
                warn!(
                    peer = peer.zid.to_string(),
                    "missing robot_id, skip reporting"
                );
                Ok(Arc::new(NoopPeerHandler))
            }
        }
    }

    fn new_multicast(
        &self,
        _transport: TransportMulticast,
    ) -> ZResult<Arc<dyn TransportMulticastEventHandler>> {
        Ok(Arc::new(NoopMulticastHandler))
    }
}

struct SessionPeerHandler {
    shared: Arc<SharedState>,
    session_id: String,
}

impl TransportPeerEventHandler for SessionPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        self.shared.on_message(&self.session_id);
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {
        self.shared
            .on_disconnect(&self.session_id, "transport_closed");
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct NoopPeerHandler;

impl TransportPeerEventHandler for NoopPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {}

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct NoopMulticastHandler;

impl TransportMulticastEventHandler for NoopMulticastHandler {
    fn new_peer(&self, _peer: TransportPeer) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        Ok(Arc::new(NoopPeerHandler))
    }

    fn closed(&self) {}

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct RunningPluginInner {
    name: String,
    config: Config,
    state: Arc<SharedState>,
}

#[derive(Clone)]
struct RunningPlugin(Arc<Mutex<RunningPluginInner>>);

impl PluginControl for RunningPlugin {
    fn report(&self) -> zenoh_plugin_trait::PluginReport {
        let guard = zlock!(self.0);
        let metrics = zlock!(guard.state.metrics);
        let mut report = zenoh_plugin_trait::PluginReport::new();
        report.add_info(format!(
            "active_sessions={} report_ok={} report_err={} keepalive_timeout={} robot_id_missing={}",
            metrics.active_sessions,
            metrics.report_ok,
            metrics.report_err,
            metrics.keepalive_timeout,
            metrics.robot_id_missing
        ));
        report
    }
}

impl RunningPluginTrait for RunningPlugin {
    fn config_checker(
        &self,
        _path: &str,
        _old: &JsonKeyValueMap,
        _new: &JsonKeyValueMap,
    ) -> ZResult<Option<JsonKeyValueMap>> {
        bail!("Runtime configuration change not supported")
    }

    fn adminspace_getter<'a>(
        &'a self,
        key_expr: &'a zenoh::key_expr::KeyExpr<'a>,
        plugin_status_key: &str,
    ) -> ZResult<Vec<zenoh::internal::plugins::Response>> {
        let guard = zlock!(self.0);
        let metrics = zlock!(guard.state.metrics);
        let mut responses = Vec::new();

        let key = format!("{plugin_status_key}/metrics");
        if KeyExpr::try_from(key.as_str())?.intersects(key_expr) {
            responses.push(zenoh::internal::plugins::Response::new(
                key,
                serde_json::json!({
                    "active_sessions": metrics.active_sessions,
                    "report_ok": metrics.report_ok,
                    "report_err": metrics.report_err,
                    "keepalive_timeout": metrics.keepalive_timeout,
                    "robot_id_missing": metrics.robot_id_missing,
                }),
            ));
        }

        let key = format!("{plugin_status_key}/config");
        if KeyExpr::try_from(key.as_str())?.intersects(key_expr) {
            responses.push(zenoh::internal::plugins::Response::new(
                key,
                serde_json::json!({
                    "name": guard.name,
                    "api_base_url": guard.config.api_base_url,
                    "project_id": guard.config.project_id,
                    "keepalive_timeout_secs": guard.config.keepalive.timeout_secs,
                }),
            ));
        }

        Ok(responses)
    }
}
