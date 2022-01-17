use regex::Regex;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::User;

pub type Tx = mpsc::UnboundedSender<Vec<u8>>;
pub type Rx = mpsc::UnboundedReceiver<Vec<u8>>;

#[derive(Debug, Clone)]
pub struct State {
    pub key: Vec<u8>,
    pub clients: HashMap<SocketAddr, Tx>,
    pub users: HashMap<String, User>,
    pub acl_regex: Regex,
}

impl State {
    pub fn new(key: Vec<u8>) -> Self {
        State {
            key,
            clients: HashMap::new(),
            users: HashMap::new(),
            acl_regex: Regex::new("").unwrap(),
        }
    }

    pub async fn unicast(&self, dest: SocketAddr, message: Vec<u8>) {
        for client in self.clients.iter() {
            if *client.0 == dest {
                let _ = client.1.send(message.into());
                break;
            }
        }
    }

    #[allow(dead_code)]
    pub async fn broadcast(&self, sender: SocketAddr, message: Vec<u8>) {
        for client in self.clients.iter() {
            if *client.0 != sender {
                let _ = client.1.send(message.clone());
            }
        }
    }
}
