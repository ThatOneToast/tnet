use serde::{Deserialize, Serialize};

use crate::{
    errors::Error,
    packet::{Packet, PacketBody},
    prelude::EncryptionConfig,
};

#[derive(Debug, Clone)]
pub struct PhantomConf<'a> {
    pub header: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub server_addr: &'a str,
    pub server_port: u16,
    pub enc_conf: EncryptionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub encryption_config: EncryptionConfig,
    pub server_addr: String,
    pub server_port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhantomPacket {
    pub header: String,
    pub body: PacketBody,
    pub sent_packet: Option<String>,
    pub recv_packet: Option<String>,
    pub client_config: Option<ClientConfig>,
}

impl PhantomPacket {
    /// Produces a `PhantomPacket` from the given configuration and underlying packet.
    /// 
    /// # Panics
    /// 
    /// This function will panic if the underlying packet cannot be serialized to JSON.
    pub fn produce_from_conf<A: Serialize>(
        conf: &PhantomConf,
        underlying_packet: A,
    ) -> Self {
        let up_ser = serde_json::to_string(&underlying_packet)
            .expect("Failed to produce PhantomPacket from UnderlyingPacket, cannot be converted to string json.");

        Self {
            header: conf.header.to_string(),
            client_config: Some(ClientConfig {
                encryption_config: conf.enc_conf.clone(),
                user: conf.username.map(ToString::to_string),
                pass: conf.password.map(ToString::to_string),
                server_port: conf.server_port,
                server_addr: conf.server_addr.to_string(),
            }),
            sent_packet: Some(up_ser),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn response() -> Self {
        Self {
            header: "relay-response".to_string(),
            ..Default::default()
        }
    }
}

impl Packet for PhantomPacket {
    fn header(&self) -> String {
        self.header.clone()
    }

    fn body(&self) -> PacketBody {
        self.body.clone()
    }

    fn body_mut(&mut self) -> &mut PacketBody {
        &mut self.body
    }

    fn ok() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody::default(),
            sent_packet: None,
            recv_packet: None,
            client_config: None,
        }
    }

    fn error(error: Error) -> Self {
        Self {
            header: "ERROR".to_string(),
            body: PacketBody::with_error_string(error.to_string().as_str()),
            ..Default::default()
        }
    }

    fn keep_alive() -> Self {
        Self {
            header: "KeepAlive".to_string(),
            ..Default::default()
        }
    }
}

impl Default for PhantomPacket {
    fn default() -> Self {
        Self {
            header: "OK".to_string(),
            body: PacketBody::default(),
            sent_packet: None,
            recv_packet: None,
            client_config: None,
        }
    }
}
