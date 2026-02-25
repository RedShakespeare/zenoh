use std::{any::Any, sync::Arc};

use tracing::warn;
use zenoh::Result as ZResult;
use zenoh_transport::{
    multicast::TransportMulticast, unicast::TransportUnicast, TransportEventHandler,
    TransportMulticastEventHandler, TransportPeer, TransportPeerEventHandler,
};

use crate::state::SharedState;

pub(crate) struct ConnectionObserver {
    shared: Arc<SharedState>,
}

impl ConnectionObserver {
    pub(crate) fn new(shared: Arc<SharedState>) -> Self {
        Self { shared }
    }

    fn resolve_robot_id(peer: &TransportPeer) -> Option<String> {
        peer.links
            .iter()
            .find_map(|link| {
                link.auth_identifier
                    .get_cert_common_name()
                    .map(str::to_string)
            })
            .or_else(|| Some(peer.zid.to_string()))
    }
}

impl TransportEventHandler for ConnectionObserver {
    fn new_unicast(
        &self,
        peer: TransportPeer,
        _transport: TransportUnicast,
    ) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        if peer.whatami != zenoh_protocol::core::WhatAmI::Client {
            return Ok(Arc::new(NoopPeerHandler));
        }

        let session_id = peer.zid.to_string();
        match Self::resolve_robot_id(&peer) {
            Some(robot_id) => {
                self.shared.on_connect(session_id.clone(), robot_id);
                Ok(Arc::new(SessionPeerHandler {
                    shared: self.shared.clone(),
                    session_id,
                }))
            }
            None => {
                self.shared.metrics.lock().unwrap().robot_id_missing += 1;
                warn!(
                    peer = peer.zid.to_string(),
                    "missing robot_id, skip reporting"
                );
                Ok(Arc::new(NoopPeerHandler))
            }
        }
    }

    fn new_multicast(
        &self,
        _transport: TransportMulticast,
    ) -> ZResult<Arc<dyn TransportMulticastEventHandler>> {
        Ok(Arc::new(NoopMulticastHandler))
    }
}

struct SessionPeerHandler {
    shared: Arc<SharedState>,
    session_id: String,
}

impl TransportPeerEventHandler for SessionPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        self.shared.on_message(&self.session_id);
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {
        self.shared
            .on_disconnect(&self.session_id, "transport_closed");
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct NoopPeerHandler;

impl TransportPeerEventHandler for NoopPeerHandler {
    fn handle_message(&self, _msg: zenoh_protocol::network::NetworkMessageMut) -> ZResult<()> {
        Ok(())
    }

    fn new_link(&self, _src: zenoh_link::Link) {}

    fn del_link(&self, _link: zenoh_link::Link) {}

    fn closed(&self) {}

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct NoopMulticastHandler;

impl TransportMulticastEventHandler for NoopMulticastHandler {
    fn new_peer(&self, _peer: TransportPeer) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        Ok(Arc::new(NoopPeerHandler))
    }

    fn closed(&self) {}

    fn as_any(&self) -> &dyn Any {
        self
    }
}
