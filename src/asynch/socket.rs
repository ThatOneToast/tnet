use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, RwLock},
};

use crate::{
    encrypt::Encryptor,
    errors::Error,
    packet::Packet,
    session::{self, Sessions},
};

#[derive(Clone)]
pub struct TSockets<S>
where
    S: session::Session,
{
    pub sockets: Arc<RwLock<Vec<TSocket<S>>>>,
}

impl<S> TSockets<S>
where
    S: session::Session,
{
    pub fn new() -> Self {
        Self {
            sockets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add(&mut self, socket: TSocket<S>) {
        self.sockets.write().await.push(socket);
    }

    pub async fn remove(&mut self, socket: &TSocket<S>) {
        self.sockets
            .write()
            .await
            .retain(|s| s.session_id != socket.session_id);
    }

    pub async fn broadcast<P: Packet>(&self, packet: P) {
        for socket in self.sockets.write().await.iter_mut() {
            socket.send(packet.clone()).await.unwrap();
        }
    }
}

#[derive(Clone)]
pub struct TSocket<S>
where
    S: session::Session,
{
    pub socket: Arc<Mutex<TcpStream>>,
    pub session_id: Option<String>,
    pub encryptor: Option<Encryptor>,
    sessions: Arc<RwLock<Sessions<S>>>,
}

impl<S> TSocket<S>
where
    S: session::Session,
{
    pub fn new(socket: TcpStream, sessions: Arc<RwLock<Sessions<S>>>) -> Self {
        Self {
            socket: Arc::new(Mutex::new(socket)),
            session_id: None,
            encryptor: None,
            sessions,
        }
    }

    pub fn with_encryptor(mut self, encryptor: Encryptor) -> Self {
        self.encryptor = Some(encryptor);
        self
    }

    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    // Add methods to access session
    pub async fn get_session(&self) -> Option<S> {
        if let Some(id) = &self.session_id {
            let sessions = self.sessions.read().await;
            sessions.get_session(id).cloned()
        } else {
            None
        }
    }

    pub async fn update_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut S) -> T,
    {
        if let Some(id) = &self.session_id {
            let mut sessions = self.sessions.write().await;
            if let Some(session) = sessions.get_session_mut(id) {
                Ok(f(session))
            } else {
                Err(Error::InvalidSessionId(id.clone()))
            }
        } else {
            Err(Error::InvalidSessionId("No session ID".to_string()))
        }
    }

    pub async fn send<P: Packet>(&mut self, packet: P) -> Result<(), Error> {
        let data = match &self.encryptor {
            Some(encryptor) => packet.encrypted_ser(encryptor),
            None => packet.ser(),
        };

        let mut socket = self.socket.lock().await;
        socket
            .write_all(&data)
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        socket
            .flush()
            .await
            .map_err(|e| Error::IoError(e.to_string()))?;
        Ok(())
    }

    // Update recv method to handle locked socket
    pub async fn recv<P: Packet>(&mut self) -> Result<P, Error> {
        let mut buf = vec![0; 4096];
        let n = {
            let mut socket = self.socket.lock().await;
            socket
                .read(&mut buf)
                .await
                .map_err(|e| Error::IoError(e.to_string()))?
        };

        if n == 0 {
            return Err(Error::ConnectionClosed);
        }

        buf.truncate(n);

        Ok(match &self.encryptor {
            Some(encryptor) => P::encrypted_de(&buf, encryptor),
            None => P::de(&buf),
        })
    }
}
