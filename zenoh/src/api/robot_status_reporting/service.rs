use zenoh_config::RobotStatusKeepaliveMode;
use zenoh_result::ZResult;

use crate::api::robot_status_reporting::{
    RobotConnectionStatus, RobotSessionRegistry, RobotStatusEvent, RobotStatusReporter,
    RobotStatusTrigger,
};

#[derive(Debug)]
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
        let robot_id = robot_id.into();
        self.registry.upsert(session_id.clone(), robot_id.clone());
        self.reporter.report(RobotStatusEvent {
            session_id,
            robot_id,
            status: RobotConnectionStatus::Online,
            trigger: RobotStatusTrigger::SessionOpen,
        })
    }

    pub(crate) fn on_transport_closed(&self, session_id: &str) -> ZResult<()> {
        if !matches!(
            self.keepalive_mode,
            RobotStatusKeepaliveMode::TransportClosedOnly | RobotStatusKeepaliveMode::Inactivity
        ) {
            return Ok(());
        }
        self.report_offline_if_needed(session_id, RobotStatusTrigger::TransportClosed)
    }

    pub(crate) fn on_inactivity_timeout(&self, session_id: &str) -> ZResult<()> {
        if !matches!(self.keepalive_mode, RobotStatusKeepaliveMode::Inactivity) {
            return Ok(());
        }
        self.report_offline_if_needed(session_id, RobotStatusTrigger::InactivityTimeout)
    }

    pub(crate) fn remove_session(&self, session_id: &str) {
        let _ = self.registry.remove(session_id);
    }

    fn report_offline_if_needed(
        &self,
        session_id: &str,
        trigger: RobotStatusTrigger,
    ) -> ZResult<()> {
        if let Some(robot_id) = self.registry.mark_offline_if_needed(session_id) {
            self.reporter.report(RobotStatusEvent {
                session_id: session_id.to_string(),
                robot_id,
                status: RobotConnectionStatus::Offline,
                trigger,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zenoh_config::RobotStatusKeepaliveMode;

    use crate::api::robot_status_reporting::{
        DryRunReporter, RobotConnectionStatus, RobotStatusService, RobotStatusTrigger,
    };

    #[test]
    fn transport_close_reports_offline_once_and_reopen_works() {
        let reporter = DryRunReporter::default();
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[2].status, RobotConnectionStatus::Online);
        assert_eq!(events[3].status, RobotConnectionStatus::Offline);
    }

    #[test]
    fn remove_session_blocks_future_offline() {
        let reporter = DryRunReporter::default();
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.remove_session("s1");
        service.on_transport_closed("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
    }

    #[test]
    fn transport_closed_only_ignores_inactivity_timeout() {
        let reporter = DryRunReporter::default();
        let service =
            RobotStatusService::new(RobotStatusKeepaliveMode::TransportClosedOnly, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::TransportClosed);
    }

    #[test]
<<<<<<< codex/implement-transport_closed_only-behavior-48s54f
    fn inactivity_timeout_reports_offline_once() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Inactivity, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::InactivityTimeout);
    }

    #[test]
    fn inactivity_timeout_and_transport_close_do_not_duplicate_offline() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Inactivity, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();
        service.on_transport_closed("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::InactivityTimeout);
    }

    #[test]
    fn transport_close_then_inactivity_timeout_do_not_duplicate_offline() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Inactivity, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::TransportClosed);
    }

    #[test]
    fn reopen_after_inactivity_timeout_allows_offline_again() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Inactivity, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();
        service.on_session_open("s1", "r1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
        assert_eq!(events[1].status, RobotConnectionStatus::Offline);
        assert_eq!(events[2].status, RobotConnectionStatus::Online);
        assert_eq!(events[3].status, RobotConnectionStatus::Offline);
        assert_eq!(events[1].trigger, RobotStatusTrigger::InactivityTimeout);
        assert_eq!(events[3].trigger, RobotStatusTrigger::InactivityTimeout);
    }

    #[test]
=======
>>>>>>> main
    fn disabled_mode_does_not_emit_offline() {
        let reporter = DryRunReporter::default();
        let service = RobotStatusService::new(RobotStatusKeepaliveMode::Disabled, reporter);

        service.on_session_open("s1", "r1").unwrap();
        service.on_transport_closed("s1").unwrap();
        service.on_inactivity_timeout("s1").unwrap();

        let events = service.reporter.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].status, RobotConnectionStatus::Online);
    }
}
