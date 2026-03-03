use std::sync::{Arc, Mutex};

use serde_json::json;
use zenoh::{
    internal::{
        bail,
        plugins::{Response, RunningPluginTrait},
        zlock,
    },
    key_expr::KeyExpr,
    Result as ZResult,
};
use zenoh_plugin_trait::{PluginControl, PluginReport};
use zenoh_util::ffi::JsonKeyValueMap;

use crate::{state::SharedState, types::Config};

pub(crate) struct RunningPluginInner {
    pub(crate) name: String,
    pub(crate) config: Config,
    pub(crate) state: Arc<SharedState>,
}

#[derive(Clone)]
pub(crate) struct RunningPlugin(pub(crate) Arc<Mutex<RunningPluginInner>>);

impl PluginControl for RunningPlugin {
    fn report(&self) -> PluginReport {
        let guard = zlock!(self.0);
        let metrics = zlock!(guard.state.metrics);
        let mut report = PluginReport::new();
        report.add_info(format!(
            "active_sessions={} report_ok={} report_err={} report_dropped_queue_full={} keepalive_timeout={}",
            metrics.active_sessions,
            metrics.report_ok,
            metrics.report_err,
            metrics.report_dropped_queue_full,
            metrics.keepalive_timeout
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
        key_expr: &'a KeyExpr<'a>,
        plugin_status_key: &str,
    ) -> ZResult<Vec<Response>> {
        let guard = zlock!(self.0);
        let metrics = zlock!(guard.state.metrics);
        let mut responses = Vec::new();

        let key = format!("{plugin_status_key}/metrics");
        if KeyExpr::try_from(key.as_str())?.intersects(key_expr) {
            responses.push(Response::new(
                key,
                json!({
                    "active_sessions": metrics.active_sessions,
                    "report_ok": metrics.report_ok,
                    "report_err": metrics.report_err,
                    "report_dropped_queue_full": metrics.report_dropped_queue_full,
                    "keepalive_timeout": metrics.keepalive_timeout,
                }),
            ));
        }

        let key = format!("{plugin_status_key}/config");
        if KeyExpr::try_from(key.as_str())?.intersects(key_expr) {
            responses.push(Response::new(
                key,
                json!({
                    "name": guard.name,
                    "api_base_url": guard.config.api_base_url,
                    "project_id": guard.config.project_id,
                    "report_mode": format!("{:?}", guard.config.report_mode).to_lowercase(),
                    "keepalive_mode": format!("{:?}", guard.config.keepalive.mode).to_lowercase(),
                    "keepalive_timeout_secs": guard.config.keepalive.timeout_secs,
                }),
            ));
        }

        Ok(responses)
    }
}


impl Drop for RunningPlugin {
    fn drop(&mut self) {
        zlock!(self.0).state.shutdown();
    }
}
