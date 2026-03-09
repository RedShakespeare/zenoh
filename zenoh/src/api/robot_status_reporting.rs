//
// Copyright (c) 2024 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! Robot status reporting domain model and dry-run reporter.
#![allow(dead_code)]
//!
//! This module intentionally avoids any HTTP dependency for now.
//! It provides:
//! - domain events (`RobotStatusEvent`)
//! - trigger/status enums
//! - in-memory session registry for `session -> robot_id`
//! - reporter abstraction + dry-run implementation for tests and integration scaffolding
//! - a service skeleton for `transport_closed_only` behavior

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
        self.events
            .lock()
            .expect("dry-run events mutex poisoned")
            .clone()
    }
}

impl RobotStatusReporter for DryRunReporter {
    fn report(&self, event: RobotStatusEvent) -> ZResult<()> {
        self.events
            .lock()
            .expect("dry-run events mutex poisoned")
            .push(event);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub(crate) fn upsert(&self, session_id: impl Into<String>, robot_id: impl Into<String>) {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .insert(
                session_id.into(),
                SessionState {
                    robot_id: robot_id.into(),
                    online_reported: false,
                    offline_reported: false,
                },
            );
    }

    pub(crate) fn remove(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .remove(session_id)
            .map(|s| s.robot_id)
    }

    pub(crate) fn robot_id(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .get(session_id)
            .map(|s| s.robot_id.clone())
    }

    pub(crate) fn len(&self) -> usize {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .len()
    }

    fn mark_online_if_needed(&self, session_id: &str) -> Option<String> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("robot session registry mutex poisoned");
        let state = sessions.get_mut(session_id)?;
        if state.online_reported {
            return None;
        }
        state.online_reported = true;
        state.offline_reported = false;
        Some(state.robot_id.clone())
    }

    fn mark_offline_if_needed(&self, session_id: &str) -> Option<String> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("robot session registry mutex poisoned");
        let state = sessions.get_mut(session_id)?;
        if state.offline_reported {
            return None;
        }
        state.offline_reported = true;
        Some(state.robot_id.clone())
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

    pub(crate) fn on_session_open(
        &self,
        session_id: impl Into<String>,
        robot_id: impl Into<String>,
    ) -> ZResult<()> {
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
            RobotStatusKeepaliveMode::TransportClosedOnly
            | RobotStatusKeepaliveMode::Inactivity => {
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
    pub(crate) fn dry_run_events(&self) -> Vec<RobotStatusEvent>
    where
        R: std::borrow::Borrow<DryRunReporter>,
    {
        self.reporter.borrow().events()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DryRunReporter, RobotConnectionStatus, RobotSessionRegistry, RobotStatusEvent,
        RobotStatusReporter, RobotStatusService, RobotStatusTrigger,
    };
    use zenoh_config::RobotStatusKeepaliveMode;

    #[test]
    fn dry_run_reporter_records_event_order() {
        let reporter = DryRunReporter::default();

        reporter
            .report(RobotStatusEvent {
                session_id: "session-1".to_string(),
                robot_id: "robot-a".to_string(),
                status: RobotConnectionStatus::Online,
                trigger: RobotStatusTrigger::SessionOpen,
            })
            .unwrap();
        reporter
            .report(RobotStatusEvent {
                session_id: "session-1".to_string(),
                robot_id: "robot-a".to_string(),
                status: RobotConnectionStatus::Offline,
                trigger: RobotStatusTrigger::TransportClosed,
            })
            .unwrap();

        let events = reporter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[0].trigger, RobotStatusTrigger::SessionOpen);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::TransportClosed);
    }

    #[test]
    fn session_registry_upsert_get_remove() {
        let registry = RobotSessionRegistry::default();

        registry.upsert("session-1", "robot-a");
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.robot_id("session-1"), Some("robot-a".to_string()));

        registry.upsert("session-1", "robot-b");
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.robot_id("session-1"), Some("robot-b".to_string()));

        assert_eq!(registry.remove("session-1"), Some("robot-b".to_string()));
        assert_eq!(registry.remove("session-1"), None);
        assert_eq!(registry.robot_id("session-1"), None);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn can_construct_inactivity_offline_event() {
        let event = RobotStatusEvent {
            session_id: "session-42".to_string(),
            robot_id: "robot-z".to_string(),
            status: RobotConnectionStatus::Offline,
            trigger: RobotStatusTrigger::InactivityTimeout,
        };

        assert_eq!(event.status, RobotConnectionStatus::Offline);
        assert_eq!(event.trigger, RobotStatusTrigger::InactivityTimeout);
        assert_eq!(event.session_id, "session-42");
        assert_eq!(event.robot_id, "robot-z");
    }

    #[test]
    fn service_reports_online_then_transport_closed_offline_once() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.dry_run_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::TransportClosed);
    }

    #[test]
    fn service_disabled_mode_does_not_report_offline_on_transport_closed() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Disabled, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.dry_run_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
    }

    #[test]
    fn service_remove_session_clears_tracking() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        assert_eq!(service.tracked_sessions(), 1);
        assert_eq!(service.remove_session("s1"), Some("r1".to_string()));
        assert_eq!(service.tracked_sessions(), 0);

        service.on_transport_closed("s1").unwrap();
        let events = service.dry_run_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
    }
    #[test]
    fn service_transport_closed_unknown_session_is_noop() {
        let reporter = DryRunReporter::default();
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_transport_closed("unknown").unwrap();
        assert!(service.dry_run_events().is_empty());
    }

    #[test]
    fn service_reopen_session_reports_online_again_after_offline() {
        let reporter = DryRunReporter::default();
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_session_open("s1", "r1").unwrap();

        let events = service.dry_run_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[2].status, RobotConnectionStatus::Online);
    }

}
