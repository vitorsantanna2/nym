// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use dashmap::DashMap;
use futures::channel::{mpsc, oneshot};
use nym_sphinx::DestinationAddressBytes;
use std::sync::Arc;

use super::websocket::message_receiver::{IsActiveRequestSender, MixMessageSender};

#[derive(Clone)]
pub(crate) struct ActiveClientsStore(
    Arc<DashMap<DestinationAddressBytes, (MixMessageSender, IsActiveRequestSender)>>,
);

impl ActiveClientsStore {
    /// Creates new instance of `ActiveClientsStore` to store in-memory handles to all currently connected clients.
    pub(crate) fn new() -> Self {
        ActiveClientsStore(Arc::new(DashMap::new()))
    }

    /// Tries to obtain sending channel to specified client. Note that if stale entry existed, it is
    /// removed and a `None` is returned instead.
    ///
    /// # Arguments
    ///
    /// * `client`: address of the client for which to obtain the handle.
    pub(crate) fn get(
        &self,
        client: DestinationAddressBytes,
    ) -> Option<(MixMessageSender, IsActiveRequestSender)> {
        let entry = self.0.get(&client)?;
        let handle = entry.value();

        // if the entry is stale, remove it from the map
        // if handle.is_valid() {
        if !handle.0.is_closed() {
            Some(handle.clone())
        } else {
            // drop the reference to the map to prevent deadlocks
            drop(entry);
            self.0.remove(&client);
            None
        }
    }

    /// Indicates particular client has disconnected from the gateway and its handle should get removed.
    ///
    /// # Arguments
    ///
    /// * `client`: address of the client for which to remove the handle.
    pub(crate) fn disconnect(&self, client: DestinationAddressBytes) {
        self.0.remove(&client);
    }

    /// Insert new client handle into the store.
    ///
    /// # Arguments
    ///
    /// * `client`: address of the client for which to insert the handle.
    /// * `handle`: the sender channel for all mix packets to be pushed back onto the websocket
    pub(crate) fn insert(
        &self,
        client: DestinationAddressBytes,
        handle: MixMessageSender,
        is_active_sender: mpsc::UnboundedSender<oneshot::Sender<bool>>,
    ) {
        self.0.insert(client, (handle, is_active_sender));
    }

    /// Get number of active clients in store
    pub(crate) fn size(&self) -> usize {
        self.0.len()
    }
}
