mod observer;
mod reporter;
mod running;
mod state;
mod types;

use std::sync::{Arc, Mutex};

use tracing::debug;
use zenoh::{
    internal::{plugins::ZenohPlugin, runtime::DynamicRuntime},
    Result as ZResult,
};
use zenoh_plugin_trait::{plugin_long_version, plugin_version, Plugin};

use crate::{
    observer::ConnectionObserver,
    reporter::spawn_background_workers,
    running::{RunningPlugin, RunningPluginInner},
    state::SharedState,
    types::Config,
};

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
