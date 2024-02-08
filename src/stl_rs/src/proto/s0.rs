use crate::proto::{Header, STL_NONCE_SZ, STL_SESSION_ID_SZ};
use ring::signature::KeyPair;
use sha2::{Digest, Sha256};

use super::{
    HandshakeHeader, STL_COOKIE_SZ, STL_SUITE_S0, STL_TYPE_HS_CLIENT_ACCEPT,
    STL_TYPE_HS_CLIENT_INITIAL, STL_TYPE_HS_SERVER_ACCEPT, STL_TYPE_HS_SERVER_CONTINUE, STL_V0,
};

// "STL v0 s0 server transcript     "
const SIGN_PREFIX_SERVER: [u8; 32] = [
    0x53, 0x54, 0x4c, 0x20, 0x76, 0x30, 0x20, 0x73, 0x30, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x20, 0x20, 0x20, 0x20, 0x20,
];

// "STL v0 s0 client transcript     "
const SIGN_PREFIX_CLIENT: [u8; 32] = [
    0x53, 0x54, 0x4c, 0x20, 0x76, 0x30, 0x20, 0x73, 0x30, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
    0x20, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x20, 0x20, 0x20, 0x20, 0x20,
];

#[repr(packed)]
pub struct HandshakePacket {
    pub header: HandshakeHeader,
    pub identity: [u8; 32],
    pub key_share: [u8; 32],
    pub verify: [u8; 64],
    pub client_nonce: [u8; STL_NONCE_SZ],
    pub server_nonce: [u8; STL_NONCE_SZ],
}

pub struct ClientParams {
    pub identity: ring::signature::Ed25519KeyPair,
    pub client_nonce: [u8; STL_NONCE_SZ],
}

impl ClientParams {
    pub fn gen_initial(&self) -> HandshakePacket {
        HandshakePacket {
            header: HandshakeHeader {
                header: Header::new(0, 0, [0; STL_SESSION_ID_SZ]),
                suite: STL_SUITE_S0,
                cookie: [0u8; STL_COOKIE_SZ],
            },
            identity: self.identity.public_key().as_ref().try_into().unwrap(),
            key_share: [0; 32],
            verify: [0; 64],
            client_nonce: self.client_nonce,
            server_nonce: [0; STL_NONCE_SZ],
        }
    }
}

pub struct ClientHandshake {
    pub transcript: Sha256,
    pub server_identity: Option<[u8; 32]>,
    pub server_nonce: [u8; STL_NONCE_SZ],
    pub state: u8,
    pub session_id: [u8; STL_SESSION_ID_SZ],
}

impl ClientHandshake {
    pub fn new() -> ClientHandshake {
        ClientHandshake {
            transcript: Sha256::new(),
            server_identity: None,
            server_nonce: [0; STL_NONCE_SZ],
            state: STL_TYPE_HS_CLIENT_INITIAL,
            session_id: [0; STL_SESSION_ID_SZ],
        }
    }

    fn handle_server_continue(
        &mut self,
        client: &ClientParams,
        packet: &HandshakePacket,
    ) -> Option<HandshakePacket> {
        if packet.header.header.type_() != STL_TYPE_HS_SERVER_CONTINUE {
            return None;
        }

        // Ignore packet if server identity is unexpected
        if let Some(expected_key) = &self.server_identity {
            if expected_key != &packet.identity {
                return None;
            }
        }

        // Create the transcript hash
        self.transcript.update(&packet.identity[..]);
        self.transcript.update(client.identity.public_key().as_ref());
        self.transcript.update(&packet.server_nonce[..]);
        self.transcript.update(&client.client_nonce[..]);
        self.transcript.update(STL_SUITE_S0.to_le_bytes());
        let commitment = self.transcript.clone().finalize();

        // Sign
        let mut signed_message: [u8; 64] = [0u8; 64];
        signed_message[0..32].copy_from_slice(&SIGN_PREFIX_CLIENT[..]);
        signed_message[32..64].copy_from_slice(&commitment[..]);
        let sig = client.identity.sign(&signed_message[..]);

        self.server_identity = Some(packet.identity);
        self.server_nonce = packet.server_nonce;
        self.state = STL_TYPE_HS_CLIENT_ACCEPT;

        // Assemble response
        Some(HandshakePacket {
            header: HandshakeHeader {
                header: Header::new(STL_V0, STL_TYPE_HS_CLIENT_ACCEPT, [0; STL_SESSION_ID_SZ]),
                suite: STL_SUITE_S0,
                cookie: packet.header.cookie,
            },
            identity: client.identity.public_key().as_ref().try_into().unwrap(),
            key_share: [0; 32],
            verify: sig.as_ref().try_into().unwrap(),
            client_nonce: client.client_nonce,
            server_nonce: packet.server_nonce,
        })
    }

    fn handle_server_accept(&mut self, packet: &HandshakePacket) {
        if packet.header.header.type_() != STL_TYPE_HS_SERVER_ACCEPT {
            return;
        }

        // Derive server commitment
        let mut transcript = self.transcript.clone();
        transcript.update(&packet.header.header.session_id[..]);
        let commitment = transcript.finalize();

        // Verify peer signature
        let mut signed_message: [u8; 64] = [0u8; 64];
        signed_message[0..32].copy_from_slice(&SIGN_PREFIX_SERVER[..]);
        signed_message[32..64].copy_from_slice(&commitment[..]);
        let peer_pubkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            self.server_identity.as_ref().unwrap(),
        );
        if peer_pubkey
            .verify(&signed_message[..], &packet.verify[..])
            .is_err()
        {
            return;
        }

        // Complete handshake
        self.state = STL_TYPE_HS_SERVER_ACCEPT;
        self.session_id = packet.header.header.session_id;
    }

    pub fn respond(
        &mut self,
        client: &ClientParams,
        packet: &HandshakePacket,
    ) -> Option<HandshakePacket> {
        if packet.header.header.version() != STL_V0
            || packet.header.suite != STL_SUITE_S0
            || packet.client_nonce != client.client_nonce
        {
            return None;
        }
        match self.state {
            STL_TYPE_HS_CLIENT_INITIAL => self.handle_server_continue(client, packet),
            STL_TYPE_HS_CLIENT_ACCEPT => {
                self.handle_server_accept(packet);
                None
            }
            _ => None,
        }
    }
}
