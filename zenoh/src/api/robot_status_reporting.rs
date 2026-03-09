//
// Copyright (c) 2024 ZettaScale Technology
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0

#![allow(dead_code)]

use std::{collections::HashMap, sync::Mutex};

use zenoh_config::RobotStatusKeepaliveMode;
use zenoh_result::ZResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RobotConnectionStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RobotStatusTrigger {
    SessionOpen,
    TransportClosed,
    InactivityTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RobotStatusEvent {
    pub(crate) session_id: String,
    pub(crate) robot_id: String,
    pub(crate) status: RobotConnectionStatus,
    pub(crate) trigger: RobotStatusTrigger,
}

pub(crate) trait RobotStatusReporter: Send + Sync {
    fn report(&self, event: RobotStatusEvent) -> ZResult<()>;
}

#[derive(Debug, Default)]
pub(crate) struct DryRunReporter {
    events: Mutex<Vec<RobotStatusEvent>>,
}

impl DryRunReporter {
    pub(crate) fn events(&self) -> Vec<RobotStatusEvent> {
        self.events.lock().expect("dry-run mutex poisoned").clone()
    }
}

impl RobotStatusReporter for DryRunReporter {
    fn report(&self, event: RobotStatusEvent) -> ZResult<()> {
        self.events.lock().expect("dry-run mutex poisoned").push(event);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SessionState {
    robot_id: String,
    online_reported: bool,
    offline_reported: bool,
}

#[derive(Debug, Default)]
pub(crate) struct RobotSessionRegistry {
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl RobotSessionRegistry {
    fn upsert(&self, session_id: String, robot_id: String) {
        self.sessions.lock().expect("registry mutex poisoned").insert(
            session_id,
            SessionState {
                robot_id,
                online_reported: false,
                offline_reported: false,
            },
        );
    }

    fn remove(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("registry mutex poisoned")
            .remove(session_id)
            .map(|s| s.robot_id)
    }

    fn mark_online_if_needed(&self, session_id: &str) -> Option<String> {
        let mut guard = self.sessions.lock().expect("registry mutex poisoned");
        let state = guard.get_mut(session_id)?;
        if state.online_reported {
            return None;
        }
        state.online_reported = true;
        state.offline_reported = false;
        Some(state.robot_id.clone())
    }

    fn mark_offline_if_needed(&self, session_id: &str) -> Option<String> {
        let mut guard = self.sessions.lock().expect("registry mutex poisoned");
        let state = guard.get_mut(session_id)?;
        if state.offline_reported {
            return None;
        }
        state.offline_reported = true;
        Some(state.robot_id.clone())
    }

    fn len(&self) -> usize {
        self.sessions.lock().expect("registry mutex poisoned").len()
    }
}

pub(crate) struct RobotStatusService<R: RobotStatusReporter> {
    keepalive_mode: RobotStatusKeepaliveMode,
    registry: RobotSessionRegistry,
    reporter: R,
}

impl<R: RobotStatusReporter> RobotStatusService<R> {
    pub(crate) fn new(keepalive_mode: RobotStatusKeepaliveMode, reporter: R) -> Self {
        Self {
            keepalive_mode,
            registry: RobotSessionRegistry::default(),
            reporter,
        }
    }

    pub(crate) fn on_session_open(&self, session_id: impl Into<String>, robot_id: impl Into<String>) -> ZResult<()> {
        let session_id = session_id.into();
        self.registry.upsert(session_id.clone(), robot_id.into());

        if let Some(robot_id) = self.registry.mark_online_if_needed(&session_id) {
            self.reporter.report(RobotStatusEvent {
                session_id,
                robot_id,
                status: RobotConnectionStatus::Online,
                trigger: RobotStatusTrigger::SessionOpen,
            })?;
        }
        Ok(())
    }

    pub(crate) fn on_transport_closed(&self, session_id: &str) -> ZResult<()> {
        match self.keepalive_mode {
            RobotStatusKeepaliveMode::Disabled => Ok(()),
            RobotStatusKeepaliveMode::TransportClosedOnly | RobotStatusKeepaliveMode::Inactivity => {
                if let Some(robot_id) = self.registry.mark_offline_if_needed(session_id) {
                    self.reporter.report(RobotStatusEvent {
                        session_id: session_id.to_string(),
                        robot_id,
                        status: RobotConnectionStatus::Offline,
                        trigger: RobotStatusTrigger::TransportClosed,
                    })?;
                }
                Ok(())
            }
        }
    }

    pub(crate) fn remove_session(&self, session_id: &str) -> Option<String> {
        self.registry.remove(session_id)
    }

    pub(crate) fn tracked_sessions(&self) -> usize {
        self.registry.len()
    }

    #[cfg(test)]
    fn events(&self) -> Vec<RobotStatusEvent>
    where
        R: std::borrow::Borrow<DryRunReporter>,
    {
        self.reporter.borrow().events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_reports_online_then_single_offline() {
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, DryRunReporter::default());

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
    }

    #[test]
    fn disabled_mode_ignores_transport_closed() {
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Disabled, DryRunReporter::default());

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
    }

    #[test]
    fn unknown_session_transport_close_is_noop() {
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, DryRunReporter::default());
        service.on_transport_closed("missing").unwrap();
        assert!(service.events().is_empty());
    }

    #[test]
    fn reopen_session_reports_online_again() {
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, DryRunReporter::default());
        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_session_open("s1", "r1").unwrap();

        let events = service.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].status, RobotConnectionStatus::Online);
    }

    #[test]
    fn remove_session_stops_future_offline() {
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, DryRunReporter::default());
        service.on_session_open("s1", "r1").unwrap();
        assert_eq!(service.tracked_sessions(), 1);
        assert_eq!(service.remove_session("s1"), Some("r1".to_string()));
        service.on_transport_closed("s1").unwrap();

        let events = service.events();
        assert_eq!(events.len(), 1);
    }
}
