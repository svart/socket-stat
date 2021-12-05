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
use netlink_packet_sock_diag::inet::nlas::Nla;
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

fn speed_human(speed: f64) -> String {
    if speed >= 1e12 {
        format!("{:.3} Tbit/s", speed / 1e12)
    } else if speed >= 1e9 {
        format!("{:.3} Gbit/s", speed / 1e9)
    } else if speed >= 1e6 {
        format!("{:.3} Mbit/s", speed / 1e6)
    } else if speed >= 1e3 {
        format!("{:.3} Mbit/s", speed / 1e3)
    } else {
        format!("{} bit/s", speed)
    }
}

fn socket_state(state: u8) -> String {
    match state {
        TCP_ESTABLISHED => format!("established"),
        TCP_SYN_SENT => format!("syn-sent"),
        TCP_SYN_RECV => format!("syn-recv"),
        TCP_FIN_WAIT1 => format!("fin-wait1"),
        TCP_FIN_WAIT2 => format!("fin-wait2"),
        TCP_TIME_WAIT => format!("time-wait"),
        TCP_CLOSE => format!("close"),
        TCP_CLOSE_WAIT => format!("close-wait"),
        TCP_LAST_ACK => format!("last-ack"),
        TCP_LISTEN => format!("listen"),
        TCP_CLOSING => format!("closing"),
        _ => format!("unknown")
    }
}

fn main() -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            message_type: SOCK_DIAG_BY_FAMILY,
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

    // Before calling serialize, it is important to check that the buffer in
    // which we're emitting is big enough for the packet, other `serialize()` panics.
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
                    // println!("{:#?}", response);
                    let src_addr = response.header.socket_id.source_address;
                    let src_port = response.header.socket_id.source_port;
                    let dst_addr = response.header.socket_id.destination_address;
                    let dst_port = response.header.socket_id.destination_port;
                    let state = response.header.state;

                    print!("{}:{}-{}:{}", src_addr, src_port, dst_addr, dst_port);
                    for nla in response.nlas {
                        match nla {
                            Nla::TcpInfo(tcp) => {
                                print!(" {}", socket_state(state));
                                print!(" cwnd: {}", tcp.snd_cwnd);

                                let rtt = tcp.rtt as f64 / 1000.;
                                let var_rtt = tcp.rttvar as f64 / 1000.;
                                print!(" rtt: {}/{}", rtt, var_rtt);

                                print!(" bytes_sent: {}", tcp.bytes_sent);
                                print!(" bytes_acked: {}", tcp.bytes_acked);
                                print!(" bytes_received: {}", tcp.bytes_received);

                                let send_bps = (tcp.snd_cwnd * tcp.snd_mss) as f64 * 8000000. / rtt;
                                print!(" send: {}", speed_human(send_bps));
                                print!(" delivery_rate: {}", speed_human(tcp.delivery_rate as f64 * 8.));
                            }
                            _ => continue,
                        }
                    }
                    println!();
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
