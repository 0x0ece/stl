use std::net::UdpSocket;

pub mod proto;

fn main() {
    let mut _args = std::env::args();

    let mut socket = UdpSocket::bind("127.0.0.1:8300").expect("Failed to bind socket");
    socket.connect("127.0.0.1:8301").expect("Failed to connect socket");
}
