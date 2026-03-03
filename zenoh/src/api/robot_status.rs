//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zenoh_protocol::core::WhatAmI;
use zenoh_result::ZResult;
use zenoh_transport::{
    multicast::TransportMulticast, unicast::TransportUnicast, TransportEventHandler,
    TransportMulticastEventHandler, TransportPeer, TransportPeerEventHandler,
};

use crate::api::session::WeakSession;

#[derive(Clone, Copy, Debug, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ReportMode {
    #[default]
    Http,
    DryRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeepaliveMode {
    #[default]
    Disabled,
    TransportClosedOnly,
    Inactivity,
}

#[derive(Debug, Clone, Deserialize)]
struct KeepaliveConfig {
    #[serde(default)]
    mode: KeepaliveMode,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            mode: KeepaliveMode::Disabled,
            timeout_secs: default_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RobotStatusRuntimeConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    api_base_url: String,
    #[serde(default)]
    auth_token: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    report_mode: ReportMode,
    #[serde(default)]
    keepalive: KeepaliveConfig,
}

fn default_timeout_secs() -> u64 {
    0
}

#[derive(Clone, Copy, Debug)]
enum RobotStatus {
    Online,
    Offline,
}

impl RobotStatus {
    fn as_str(self) -> &'static str {
        match self {
            RobotStatus::Online => "ONLINE",
            RobotStatus::Offline => "OFFLINE",
        }
    }
}

struct SessionRecord {
    robot_id: String,
    last_keepalive: Instant,
}

struct ReportCommand {
    robot_id: String,
    status: RobotStatus,
}

struct SharedState {
    cfg: RobotStatusRuntimeConfig,
    sessions: Mutex<HashMap<String, SessionRecord>>,
    tx: mpsc::Sender<ReportCommand>,
    rx: Mutex<Option<mpsc::Receiver<ReportCommand>>>,
    shutdown: CancellationToken,
}

impl SharedState {
    fn new(cfg: RobotStatusRuntimeConfig) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(2048);
        Arc::new(Self {
            cfg,
            sessions: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(Some(rx)),
            shutdown: CancellationToken::new(),
        })
    }

    fn on_connect(&self, session_id: String, robot_id: String) {
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .insert(
                session_id,
                SessionRecord {
                    robot_id: robot_id.clone(),
                    last_keepalive: Instant::now(),
                },
            );
        self.enqueue_report(robot_id, RobotStatus::Online);
    }

    fn on_message(&self, session_id: &str) {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("sessions lock poisoned")
            .get_mut(session_id)
        {
            record.last_keepalive = Instant::now();
        }
    }

    fn on_disconnect(&self, session_id: &str, reason: &str) {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("sessions lock poisoned")
            .remove(session_id)
        {
            info!(
                session_id,
                robot_id = record.robot_id,
                reason,
                "robot session disconnected"
            );
            self.enqueue_report(record.robot_id, RobotStatus::Offline);
        }
    }

    fn enqueue_report(&self, robot_id: String, status: RobotStatus) {
        if let Err(e) = self.tx.try_send(ReportCommand { robot_id, status }) {
            warn!("dropping robot status report command: {e}");
        }
    }

    fn take_rx(&self) -> Option<mpsc::Receiver<ReportCommand>> {
        self.rx.lock().expect("rx lock poisoned").take()
    }

    fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

pub(crate) fn maybe_register(runtime: &crate::net::runtime::GenericRuntime, session: WeakSession) {
    let cfg = match runtime
        .get_config()
        .get_typed::<RobotStatusRuntimeConfig>("robot_status_reporting")
    {
        Ok(cfg) => cfg,
        Err(err) => {
            warn!("failed to parse robot_status_reporting config: {err}");
            RobotStatusRuntimeConfig::default()
        }
    };

    if !cfg.enabled {
        return;
    }

    if cfg.api_base_url.is_empty() || cfg.project_id.is_empty() {
        warn!(
            "robot_status_reporting is enabled but api_base_url/project_id are empty; feature disabled"
        );
        return;
    }

    let state = SharedState::new(cfg);
    runtime.new_handler(Arc::new(RobotStatusObserver {
        state: state.clone(),
        session,
    }));
    spawn_workers(state);
    info!("robot_status_reporting enabled");
}

fn spawn_workers(state: Arc<SharedState>) {
    if let Some(mut rx) = state.take_rx() {
        let report_state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = report_state.shutdown.cancelled() => break,
                    cmd = rx.recv() => {
                        let Some(cmd) = cmd else { break; };
                        if let Err(e) = send_report(&report_state.cfg, &cmd) {
                            error!(robot_id = cmd.robot_id, status = cmd.status.as_str(), "{e}");
                        }
                    }
                }
            }
        });
    }

    if state.cfg.keepalive.mode != KeepaliveMode::Inactivity
        || state.cfg.keepalive.timeout_secs == 0
    {
        return;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = state.shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let timeout = Duration::from_secs(state.cfg.keepalive.timeout_secs);
                    let stale: Vec<String> = {
                        state
                            .sessions
                            .lock()
                            .expect("sessions lock poisoned")
                            .iter()
                            .filter_map(|(id, rec)| (rec.last_keepalive.elapsed() >= timeout).then_some(id.clone()))
                            .collect()
                    };
                    for session_id in stale {
                        state.on_disconnect(&session_id, "keepalive_timeout");
                    }
                }
            }
        }
    });
}

fn send_report(cfg: &RobotStatusRuntimeConfig, cmd: &ReportCommand) -> Result<(), String> {
    let url = format!(
        "{}/v1/{}/robots/{}/status?status={}",
        cfg.api_base_url.trim_end_matches('/'),
        cfg.project_id,
        cmd.robot_id,
        cmd.status.as_str()
    );

    if matches!(cfg.report_mode, ReportMode::DryRun) {
        info!(
            url,
            status = cmd.status.as_str(),
            robot_id = cmd.robot_id,
            "robot status dry_run"
        );
        return Ok(());
    }

    match ureq::patch(&url)
        .set("X-Auth-Token", &cfg.auth_token)
        .call()
    {
        Ok(resp) if resp.status() == 200 => Ok(()),
        Ok(resp) => Err(format!("unexpected HTTP status {}", resp.status())),
        Err(ureq::Error::Status(code, _)) => Err(format!("unexpected HTTP status {code}")),
        Err(err) => Err(err.to_string()),
    }
}

struct RobotStatusObserver {
    state: Arc<SharedState>,
    session: WeakSession,
}

impl TransportEventHandler for RobotStatusObserver {
    fn new_unicast(
        &self,
        peer: TransportPeer,
        _transport: TransportUnicast,
    ) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        if self.session.session().is_closed() || peer.whatami != WhatAmI::Client {
            return Ok(Arc::new(NoopPeerHandler));
        }

        let session_id = peer.zid.to_string();
        // Certificate-based extraction will be extended once the final cert parsing contract is defined.
        let robot_id = peer.zid.to_string();

        self.state.on_connect(session_id.clone(), robot_id);
        Ok(Arc::new(RobotPeerHandler {
            state: self.state.clone(),
            session_id,
        }))
    }

    fn new_multicast(
        &self,
        _transport: TransportMulticast,
    ) -> ZResult<Arc<dyn TransportMulticastEventHandler>> {
        Ok(Arc::new(NoopMulticastHandler))
    }
}

struct RobotPeerHandler {
    state: Arc<SharedState>,
    session_id: String,
}

impl TransportPeerEventHandler for RobotPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        self.state.on_message(&self.session_id);
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {
        self.state
            .on_disconnect(&self.session_id, "transport_closed");
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Drop for RobotStatusObserver {
    fn drop(&mut self) {
        self.state.shutdown();
    }
}

struct NoopPeerHandler;

impl TransportPeerEventHandler for NoopPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {}

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct NoopMulticastHandler;

impl TransportMulticastEventHandler for NoopMulticastHandler {
    fn new_peer(&self, _peer: TransportPeer) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        Ok(Arc::new(NoopPeerHandler))
    }

    fn closed(&self) {}

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
