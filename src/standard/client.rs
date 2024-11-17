use std::{
    io::{Read, Write},
    net::TcpStream,
};

use t_logger::prelude::*;

use crate::{
    packet::{NetErrorPacket, NetWrapperPacket, Packet},
    prelude::Session,
};

/// A network client that manages connection and communication with a server
///
/// The Client handles session management, packet sending/receiving, and maintains
/// the connection state with the server.
///
/// # Type Parameters
/// * `S` - Type implementing Session trait for managing client session data
///
/// # Fields
/// * `session_id` - Optional unique identifier for the current session
/// * `server` - TCP connection to the server
/// * `last_session_data` - Cache of the most recent session data received
///
/// # Example
/// ```rust
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct GameSession {
///     player_name: String,
///     score: u32,
/// }
///
/// impl Session for GameSession {
///     fn get_id(&self) -> String {
///         uuid::Uuid::new_v4().to_string()
///     }
///
///     fn encode(&self) -> Vec<u8> {
///         bincode::serialize(self).unwrap()
///     }
///
///     fn decode(data: &[u8]) -> Self {
///         bincode::deserialize(data).unwrap()
///     }
/// }
///
/// #[derive(Serialize, Deserialize)]
/// enum GamePacket {
///     Move { x: f32, y: f32 },
///     Chat { message: String },
/// }
///
/// impl Packet for GamePacket {
///     fn encode(&self) -> Vec<u8> {
///         bincode::serialize(self).unwrap()
///     }
///
///     fn decode(data: &[u8]) -> Self {
///         bincode::deserialize(data).unwrap()
///     }
/// }
///
/// fn main() -> Result<(), std::io::Error> {
///     // Connect to server
///     let mut client = Client::<GameSession>::connect("127.0.0.1:8080")?;
///
///     // Establish session
///     client.establish_session("player1".to_string(), "password123".to_string())?;
///
///     // Send a game packet
///     let move_packet = GamePacket::Move { x: 10.0, y: 20.0 };
///     client.send_packet(move_packet, false)?;
///
///     // Receive response
///     let response: GamePacket = client.receive_packet()?;
///
///     Ok(())
/// }
/// ```
pub struct Client<S: Session> {
    session_id: Option<String>,
    server: TcpStream,
    last_session_data: Option<S>,
}

impl<S: Session> Client<S> {
    /// Creates a new Client instance from an existing TcpStream
    ///
    /// # Arguments
    /// * `server` - An established TcpStream connection to the server
    ///
    /// # Returns
    /// A new Client instance with no session established
    pub fn new(server: TcpStream) -> Self {
        Self {
            session_id: None,
            server,
            last_session_data: None,
        }
    }

    /// Returns the current session ID if one is established
    ///
    /// # Returns
    /// An Option containing the session ID string if authenticated, None otherwise
    pub fn ses_id(&self) -> Option<String> {
        self.session_id.clone()
    }

    /// Creates a new Client by connecting to a server address
    ///
    /// # Arguments
    /// * `addr` - Server address string (e.g., "127.0.0.1:8080")
    ///
    /// # Returns
    /// Result containing either a new Client instance or an IO error
    ///
    /// # Errors
    /// Returns an error if the connection cannot be established
    pub fn connect(addr: &str) -> Result<Self, std::io::Error> {
        Ok(Self {
            session_id: None,
            server: TcpStream::connect(addr)?,
            last_session_data: None,
        })
    }

    /// Establishes an authenticated session with the server
    ///
    /// Sends authentication credentials to the server and processes the response.
    /// If successful, stores the session ID for future communications.
    ///
    /// # Arguments
    /// * `user` - Username for authentication
    /// * `pass` - Password for authentication
    ///
    /// # Returns
    /// Result indicating success or containing an IO error
    ///
    /// # Errors
    /// * Returns an error if authentication fails
    /// * Returns an error if there are network issues
    ///
    /// # Panics
    /// Panics if the server returns an unexpected packet type
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

        debug_box!("Establishing...", "Recieved a response: {:?}", packet);
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
        success!(
            "Established Connection!",
            "Got session id: {:?}",
            self.session_id
        );

        Ok(())
    }

    /// Receives and decodes a packet from the server
    ///
    /// Receives the next packet from the server, updates the session data,
    /// and returns the decoded packet.
    ///
    /// # Type Parameters
    /// * `P` - Type implementing the Packet trait
    ///
    /// # Returns
    /// Result containing either the decoded packet or an IO error
    ///
    /// # Errors
    /// Returns an error if there are network issues or the packet cannot be decoded
    pub fn receive_packet<P: Packet>(&mut self) -> Result<P, std::io::Error> {
        let mut buffer = [0; 1024];
        self.server.read(&mut buffer)?;

        let packet: NetWrapperPacket = NetWrapperPacket::decode(&buffer);

        let underlying_packet: P = P::decode(packet.packet.unwrap().as_slice());
        let session_data: S = S::decode(packet.session_data.unwrap().as_slice());

        self.last_session_data = Some(session_data);

        Ok(underlying_packet)
    }

    /// Sends a packet to the server
    ///
    /// Encodes and sends a packet to the server, either as an authenticated
    /// request or as a passthrough packet.
    ///
    /// # Arguments
    /// * `packet` - The packet to send, implementing the Packet trait
    /// * `passthrough` - If true, sends without authentication; if false, includes session ID
    ///
    /// # Returns
    /// Result indicating success or containing an IO error
    ///
    /// # Errors
    /// Returns an error if there are network issues
    ///
    /// # Panics
    /// May panic if `passthrough` is false and no session is established
    pub fn send_packet<P: Packet>(
        &mut self,
        packet: P,
        passthrough: bool,
    ) -> Result<(), std::io::Error> {
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

        self.server.write(&packet.encode())?;
        self.server.flush()?; // Ensure the packet is sent immediately

        Ok(())
    }
}
