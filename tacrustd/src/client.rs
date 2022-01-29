use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio_util::codec::{BytesCodec, Framed};

use std::io;
use std::sync::Arc;

use crate::state::Rx;
use crate::state::State;

pub struct Client {
    pub pipe: Framed<TcpStream, BytesCodec>,
    pub rx: Rx,
}

impl Client {
    pub async fn new(
        shared_state: Arc<RwLock<State>>,
        pipe: Framed<TcpStream, BytesCodec>,
    ) -> io::Result<Client> {
        let addr = pipe.get_ref().peer_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();

        shared_state.write().await.clients.insert(addr, tx);

        Ok(Client { pipe, rx })
    }
}
