use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Mutex,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionState {
    robot_id: String,
    offline_reported: bool,
}

#[derive(Debug, Default)]
pub(crate) struct RobotSessionRegistry {
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl RobotSessionRegistry {
    pub(crate) fn upsert(&self, session_id: impl Into<String>, robot_id: impl Into<String>) {
        let session_id = session_id.into();
        let robot_id = robot_id.into();

        match self
            .sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .entry(session_id)
        {
            Entry::Occupied(mut o) => {
                let state = o.get_mut();
                state.robot_id = robot_id;
                state.offline_reported = false;
            }
            Entry::Vacant(v) => {
                v.insert(SessionState {
                    robot_id,
                    offline_reported: false,
                });
            }
        }
    }

    pub(crate) fn remove(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .remove(session_id)
            .map(|state| state.robot_id)
    }

    pub(crate) fn robot_id(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .get(session_id)
            .map(|state| state.robot_id.clone())
    }

    pub(crate) fn mark_offline_if_needed(&self, session_id: &str) -> Option<String> {
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

    pub(crate) fn len(&self) -> usize {
        self.sessions
            .lock()
            .expect("robot session registry mutex poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use crate::api::robot_status_reporting::RobotSessionRegistry;

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
    fn session_registry_offline_deduplicates_until_reopen() {
        let registry = RobotSessionRegistry::default();
        registry.upsert("session-1", "robot-a");

        assert_eq!(
            registry.mark_offline_if_needed("session-1"),
            Some("robot-a".to_string())
        );
        assert_eq!(registry.mark_offline_if_needed("session-1"), None);

        registry.upsert("session-1", "robot-a");
        assert_eq!(
            registry.mark_offline_if_needed("session-1"),
            Some("robot-a".to_string())
        );
    }
}
