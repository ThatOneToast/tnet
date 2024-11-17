pub mod packet;
pub mod prelude;
pub mod session;
pub mod standard;

#[cfg(test)]
mod tests {
    use std::{io::Write, net::TcpStream};
    use super::prelude::*;
    use t_logger::prelude::*;
    use uuid::Uuid;
    use crate::{
        packet::NetWrapperPacket,
        standard::{client::Client, listener::Listener},
    };

    #[derive(DPacket, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestPacket(u8, String, bool);

    impl Default for TestPacket {
        fn default() -> Self {
            Self(0, String::new(), false)
        }
    }

    #[derive(DSession, Debug, Clone, Serialize, Deserialize)]
    struct TestSession {
        #[session_id]
        id: String,
        a: bool,
        b: bool,
    }

    impl Default for TestSession {
        fn default() -> Self {
            Self {
                id: Uuid::new_v4().to_string(),
                a: false,
                b: false,
            }
        }
    }

    fn ok(session: &mut TestSession, packet: TestPacket, stream: &mut TcpStream) {
        success_box!(
            format!("[HANDLER] New Packet - {}", session.id).as_str(),
            "{:?}",
            packet
        );
        
        stream.write(
            NetWrapperPacket::just_this(
                TestPacket::default(), 
                session.clone()
            ).encode().as_slice()
        ).unwrap();
    }

    #[test]
    fn start() {
        let mut server = Listener::new("127.0.0.1:5050");
        server.set_handler(Box::new(ok));
        server.allow_passthrough = false;
        server.listen();
    }

    #[test]
    fn client() {
        let mut client: Client<TestSession> = Client::connect("127.0.0.1:5050").unwrap();
        client
            .establish_session("toast".to_string(), "toast".to_string())
            .unwrap();
        client.send_packet(TestPacket::default(), false).unwrap();

        let packet: TestPacket = client.receive_packet().unwrap();

        if packet == TestPacket::default() {
            success_box!("Client", "Packet Received");
        } else {
            error_box!("Client", "Packet Received {:?}", packet);
        }
    }
}
