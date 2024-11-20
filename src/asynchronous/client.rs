use tlogger::prelude::*;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::packet::NetErrorPacket;
use crate::packet::NetWrapperPacket;
use crate::prelude::*;

pub struct Client<S: Session> {
    session_id: Option<String>,
    server: TcpStream,
    last_session_data: Option<S>,
}

impl<S: Session> Client<S> {
    pub async fn connect(addr: &str) -> Result<Self, std::io::Error> {
        Ok(Self {
            session_id: None,
            server: TcpStream::connect(addr).await?,
            last_session_data: None,
        })
    }
    
    pub async fn establish_session(&mut self, user: String, pass: String) -> Result<(), std::io::Error> {
        let ses_packet = NetWrapperPacket {
            action_id: 1,
            username: Some(user),
            password: Some(pass),
            ..Default::default()
        };
        self.server.write(&ses_packet.encode()).await?;
        
        let mut buffer = [0; 1024];
        self.server.read(&mut buffer).await?;
        
        let packet: NetWrapperPacket = NetWrapperPacket::decode(&buffer);
        
        debug_box!("Establishing...", "Recieved a response: {:?}", packet);
        if packet.action_id != 1 {
            if packet.action_id == 2 {
                let error_packet: NetErrorPacket = NetErrorPacket::decode(&packet.packet.unwrap());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error_packet.error,
                ));
            } else {
                error!(
                    "Critical Error",
                    "When establishing a session, got an unexpected packet type"
                );
                panic!("Something horrible happened.");
            }
        }
        
        self.session_id = Some(packet.session_id);
        success!(
            "Established Connection!",
            "Got session id: {:?}",
            self.session_id
        );
        
        Ok(())
    }
    
    pub async fn receive_packet<P: Packet>(&mut self) -> Result<P, std::io::Error> {
        let mut buffer = [0; 1024];
        self.server.read(&mut buffer).await?;
        
        let packet: NetWrapperPacket = NetWrapperPacket::decode(&buffer);
        
        let underlying_packet: P = P::decode(packet.packet.unwrap().as_slice());
        let session_data: S = S::decode(packet.session_data.unwrap().as_slice());
        
        self.last_session_data = Some(session_data);
        
        Ok(underlying_packet)
    }
    
    pub async fn send_packet<P: Packet>(&mut self, packet: P, passthrough: bool) -> Result<(), std::io::Error> {
        debug!("Packet Send", "Getting ready to send packet");
        let packet: NetWrapperPacket = NetWrapperPacket {
            action_id: match passthrough {
                true => 0,
                false => 3,
            },
            session_id: match passthrough {
                true => "".to_string(),
                false => self.session_id.clone().unwrap(),
            },
            packet: Some(packet.encode()),
            ..Default::default()
        };
        
        debug!("Packet Send", "Sending packet");
        
        self.server.write(&packet.encode()).await?;
        self.server.flush().await?; // Ensure the packet is sent immediately
        
        Ok(())
    }
}