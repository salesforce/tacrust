use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::{BytesCodec, Framed};

use std::io;
use std::sync::Arc;

use crate::state::Rx;
use crate::state::State;

struct Client {
    pipe: Framed<TcpStream, BytesCodec>,
    rx: Rx,
}

impl Client {
    async fn new(
        state: Arc<Mutex<State>>,
        pipe: Framed<TcpStream, BytesCodec>,
    ) -> io::Result<Client> {
        let addr = pipe.get_ref().peer_addr()?;
        let (tx, rx) = mpsc::unbounded_channel();
        state.lock().await.clients.insert(addr, tx);

        Ok(Client { pipe, rx })
    }
}
