use std::{sync::Arc, time::Duration};

use tokio::time::MissedTickBehavior;
use tracing::{error, warn};
use zenoh::internal::zlock;

use crate::{
    state::SharedState,
    types::{Config, ReportCommand},
};

pub(crate) fn spawn_background_workers(shared: Arc<SharedState>) {
    spawn_report_worker(shared.clone());
    spawn_keepalive_scanner(shared);
}

fn spawn_report_worker(shared: Arc<SharedState>) {
    if let Some(mut rx) = shared.take_report_rx() {
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let result = send_patch_report(&shared.config, &cmd);
                match result {
                    Ok(code) if code == 200 => {
                        zlock!(shared.metrics).report_ok += 1;
                        shared.update_report_result(&cmd.session_id, Some(code), None);
                    }
                    Ok(code) => {
                        zlock!(shared.metrics).report_err += 1;
                        shared.update_report_result(
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
                        zlock!(shared.metrics).report_err += 1;
                        shared.update_report_result(&cmd.session_id, None, Some(e.clone()));
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
}

fn spawn_keepalive_scanner(shared: Arc<SharedState>) {
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
