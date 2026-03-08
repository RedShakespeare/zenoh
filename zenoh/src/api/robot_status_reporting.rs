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

use std::{collections::HashMap, sync::Mutex};

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

#[derive(Debug, Default)]
pub(crate) struct RobotSessionRegistry {
    sessions: Mutex<HashMap<String, String>>,
}

impl RobotSessionRegistry {
    pub(crate) fn upsert(&self, session_id: impl Into<String>, robot_id: impl Into<String>) {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .insert(session_id.into(), robot_id.into());
    }

    pub(crate) fn remove(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .remove(session_id)
    }

    pub(crate) fn robot_id(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .get(session_id)
            .cloned()
    }

    pub(crate) fn len(&self) -> usize {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DryRunReporter, RobotConnectionStatus, RobotSessionRegistry, RobotStatusEvent,
        RobotStatusReporter, RobotStatusTrigger,
    };

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
}
