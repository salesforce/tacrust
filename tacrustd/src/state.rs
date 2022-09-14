use regex::Regex;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, RwLock};

use crate::{Acl, Group, User};

pub type Tx = mpsc::UnboundedSender<Vec<u8>>;
pub type Rx = mpsc::UnboundedReceiver<Vec<u8>>;

#[derive(Debug, Clone)]
pub struct State {
    pub key: Vec<u8>,
    pub extra_keys: Vec<Vec<u8>>,
    pub pam_service: String,
    pub upstream_tacacs_server: String,
    pub upstream_tacacs_connections: HashMap<SocketAddr, Arc<std::sync::RwLock<TcpStream>>>,
    pub sockets: HashMap<SocketAddr, Tx>,
    pub maps: HashMap<IpAddr, Arc<RwLock<HashMap<String, String>>>>,
    pub regexes: HashMap<String, Arc<Regex>>,
    pub acls: HashMap<String, Arc<Acl>>,
    pub users: HashMap<String, Arc<User>>,
    pub groups: HashMap<String, Arc<Group>>,
}

impl State {
    pub fn new(
        key: Vec<u8>,
        extra_keys: Vec<Vec<u8>>,
        pam_service: String,
        upstream_tacacs_server: String,
    ) -> Self {
        State {
            key,
            extra_keys,
            pam_service,
            upstream_tacacs_server,
            upstream_tacacs_connections: HashMap::new(),
            sockets: HashMap::new(),
            maps: HashMap::new(),
            regexes: HashMap::new(),
            acls: HashMap::new(),
            users: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    pub async fn unicast(&self, dest: SocketAddr, message: Vec<u8>) {
        if !self.sockets.contains_key(&dest) {
            return;
        }
        let _ = self.sockets.get(&dest).unwrap().send(message.into());
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
