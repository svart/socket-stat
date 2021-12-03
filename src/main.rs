// SPDX-License-Identifier: MIT
use std::io;

use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    NetlinkHeader,
    NetlinkMessage,
    NetlinkPayload,
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

fn main() -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::all(),
            states: StateFlags::all(),
            socket_id: SocketId::new_v4(),
        })
            .into(),
    };

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in which we're emitting is big
    // enough for the packet, other `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    if let Err(e) = socket.send(&buf[..], 0) {
        panic!("Cannot send request: {}", e);
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    println!("{:#?}", response);
                }
                NetlinkPayload::Done => {
                    return Ok(());
                }
                NetlinkPayload::Error(e) => {
                    return Err(e.to_io());
                }
                NetlinkPayload::Overrun(_) | _ => {
                    return Err(io::Error::new(io::ErrorKind::Other, "unknown error"));
                }
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
    Ok(())
}
