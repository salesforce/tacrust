use std::net::{IpAddr, SocketAddr};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, RwLock};

use crate::{Acl, Group, User};

pub type Tx = mpsc::UnboundedSender<Vec<u8>>;
pub type Rx = mpsc::UnboundedReceiver<Vec<u8>>;

#[derive(Debug, Clone)]
pub struct State {
    pub key: Vec<u8>,
    pub sockets: HashMap<SocketAddr, Tx>,
    pub maps: HashMap<IpAddr, Arc<RwLock<HashMap<String, String>>>>,
    pub acls: HashMap<String, Acl>,
    pub users: HashMap<String, User>,
    pub groups: HashMap<String, Group>,
}

impl State {
    pub fn new(key: Vec<u8>) -> Self {
        State {
            key,
            sockets: HashMap::new(),
            maps: HashMap::new(),
            acls: HashMap::new(),
            users: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    pub async fn unicast(&self, dest: SocketAddr, message: Vec<u8>) {
        for client in self.sockets.iter() {
            if *client.0 == dest {
                let _ = client.1.send(message.into());
                break;
            }
        }
    }

    #[allow(dead_code)]
    pub async fn broadcast(&self, sender: SocketAddr, message: Vec<u8>) {
        for client in self.sockets.iter() {
            if *client.0 != sender {
                let _ = client.1.send(message.clone());
            }
        }
    }
}
