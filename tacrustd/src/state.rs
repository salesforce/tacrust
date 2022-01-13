use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{BytesCodec, Framed};

use futures::SinkExt;
use std::collections::HashMap;
use std::net::SocketAddr;

pub type Tx = mpsc::UnboundedSender<Vec<u8>>;
pub type Rx = mpsc::UnboundedReceiver<Vec<u8>>;

pub struct State {
    pub clients: HashMap<SocketAddr, Tx>,
}

impl State {
    pub fn new() -> Self {
        State {
            clients: HashMap::new(),
        }
    }

    async fn unicast(&mut self, sender: SocketAddr, message: Vec<u8>) {
        for client in self.clients.iter_mut() {
            if *client.0 == sender {
                let _ = client.1.send(message.into());
                break;
            }
        }
    }

    async fn broadcast(&mut self, sender: SocketAddr, message: Vec<u8>) {
        for client in self.clients.iter_mut() {
            if *client.0 != sender {
                let _ = client.1.send(message.clone());
            }
        }
    }
}
