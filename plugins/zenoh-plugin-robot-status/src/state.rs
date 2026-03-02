use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use zenoh::internal::zlock;

use crate::types::{now_epoch_ms, Config, Metrics, ReportCommand, RobotStatus, SessionRecord};

pub(crate) struct SharedState {
    pub(crate) config: Config,
    pub(crate) sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
    pub(crate) metrics: Arc<Mutex<Metrics>>,
    report_tx: mpsc::Sender<ReportCommand>,
    report_rx: Mutex<Option<mpsc::Receiver<ReportCommand>>>,
    shutdown: CancellationToken,
}

impl SharedState {
    pub(crate) fn new(config: Config) -> Self {
        let (report_tx, report_rx) = mpsc::channel(2048);
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Mutex::new(Metrics::default())),
            report_tx,
            report_rx: Mutex::new(Some(report_rx)),
            shutdown: CancellationToken::new(),
        }
    }

    pub(crate) fn on_connect(&self, session_id: String, robot_id: String) {
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

    pub(crate) fn on_message(&self, session_id: &str) {
        if let Some(record) = zlock!(self.sessions).get_mut(session_id) {
            record.last_keepalive = Instant::now();
        }
    }

    pub(crate) fn on_disconnect(&self, session_id: &str, reason: &str) {
        let mut sessions = zlock!(self.sessions);
        let removed = sessions.remove(session_id);
        zlock!(self.metrics).active_sessions = sessions.len();
        drop(sessions);
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

    pub(crate) fn enqueue_report(&self, session_id: String, robot_id: String, status: RobotStatus) {
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

    pub(crate) fn update_report_result(
        &self,
        session_id: &str,
        code: Option<u16>,
        error: Option<String>,
    ) {
        if let Some(session) = zlock!(self.sessions).get_mut(session_id) {
            session.last_report_code = code;
            session.last_report_error = error;
        }
    }

    pub(crate) fn take_report_rx(&self) -> Option<mpsc::Receiver<ReportCommand>> {
        zlock!(self.report_rx).take()
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

