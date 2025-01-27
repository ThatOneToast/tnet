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

    pub async fn session_clone(&self) -> Option<S> {
        if let Some(id) = &self.session_id {
            let sessions = self.sessions.read().await;
            sessions.get_session(id).cloned()
        } else {
            None
        }
    }

    pub async fn send<P: Packet>(&mut self, packet: P) -> Result<(), Error> {
        let data = match &self.encryptor {
            Some(encryptor) => {
                println!("TSocket encrypting packet");
                packet.encrypted_ser(encryptor)
            }
            None => {
                println!("TSocket sending unencrypted packet");
                packet.ser()
            }
        };

        println!("TSocket sending {} bytes", data.len());
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

        println!("TSocket received {} bytes", n);
        buf.truncate(n);

        Ok(match &self.encryptor {
            Some(encryptor) => {
                println!("TSocket decrypting packet");
                P::encrypted_de(&buf, encryptor)
            }
            None => P::de(&buf),
        })
    }
}
