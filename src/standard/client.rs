use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::{
    packet::{NetErrorPacket, NetWrapperPacket, Packet},
    prelude::Session,
};

pub struct Client<S: Session> {
    session_id: Option<String>,
    server: TcpStream,
    last_session_data: Option<S>,
}

impl<S: Session> Client<S> {
    pub fn new(server: TcpStream) -> Self {
        Self {
            session_id: None,
            server,
            last_session_data: None,
        }
    }

    pub fn connect(addr: &str) -> Result<Self, std::io::Error> {
        Ok(Self {
            session_id: None,
            server: TcpStream::connect(addr)?,
            last_session_data: None,
        })
    }
    /// Establish a session with the server.
    ///
    /// This function will panic if the server returns an invalid packet.
    pub fn establish_session(&mut self, user: String, pass: String) -> Result<(), std::io::Error> {
        let ses_packet = NetWrapperPacket {
            action_id: 1,
            username: Some(user),
            password: Some(pass),
            ..Default::default()
        };
        self.server.write(&ses_packet.encode())?;

        let mut buffer = [0; 1024];
        self.server.read(&mut buffer)?;

        let packet: NetWrapperPacket = NetWrapperPacket::decode(&buffer);
        
        if packet.action_id != 1 {
            if packet.action_id == 2 {
                let error_packet: NetErrorPacket = NetErrorPacket::decode(&packet.packet.unwrap());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    error_packet.error,
                ));
            } else {
                panic!("Something horrible happened.");
            }
        }

        self.session_id = Some(packet.session_id);
        println!("Got session id: {:?}", self.session_id);

        Ok(())
    }

    pub fn receive_packet<P: Packet>(&mut self) -> Result<P, std::io::Error> {
        let mut buffer = [0; 1024];
        self.server.read(&mut buffer)?;

        let packet: NetWrapperPacket = NetWrapperPacket::decode(&buffer);

        let underlying_packet: P = P::decode(packet.packet.unwrap().as_slice());
        let session_data: S = S::decode(packet.session_data.unwrap().as_slice());

        self.last_session_data = Some(session_data);

        Ok(underlying_packet)
    }

    pub fn send_packet<P: Packet>(
        &mut self,
        packet: P,
        passthrough: bool,
    ) -> Result<(), std::io::Error> {
        println!("Getting ready to send packet");
        let packet: NetWrapperPacket = NetWrapperPacket {
            action_id: match passthrough {
                true => 0,
                false => 3,
            },
            session_id: match passthrough {
                true => "".to_string(),
                false => self.session_id.clone().unwrap()
            },
            packet: Some(packet.encode()),
            ..Default::default()
        };
        
        println!("Sending packet");
        
        self.server.write(&packet.encode())?;

        Ok(())
    }
}
