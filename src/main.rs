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
use netlink_packet_sock_diag::inet::InetResponse;
use netlink_packet_sock_diag::inet::nlas::{Nla, TcpInfo};
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

fn display_af_proto(af: u8, proto: u8) -> String {
    match (af, proto) {
        (AF_INET, IPPROTO_TCP) => format!("tcp"),
        (AF_INET, IPPROTO_UDP) => format!("udp"),
        _ => format!("unknown")
    }
}

fn tcp_info_handler(tcp: TcpInfo) {
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

fn process_netlink_responses(af: u8, proto: u8, responses: Vec<Box<InetResponse>>) {
    for response in responses {
        let src_addr = response.header.socket_id.source_address;
        let src_port = response.header.socket_id.source_port;
        let dst_addr = response.header.socket_id.destination_address;
        let dst_port = response.header.socket_id.destination_port;
        print!("{} {}:{}-{}:{}",
               display_af_proto(af, proto), src_addr, src_port, dst_addr, dst_port);

        let state = response.header.state;
        print!(" {}", socket_state(state));

        for nla in response.nlas {
            match nla {
                Nla::TcpInfo(tcp) => {
                    tcp_info_handler(tcp);
                }
                _ => continue,
            }
        }
        println!();
    }
}

fn send_request(socket: &mut Socket, af: u8, proto: u8) -> io::Result<()>{
    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            message_type: SOCK_DIAG_BY_FAMILY,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: af,
            protocol: proto,
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

    socket.send(&buf[..], 0)?;
    Ok(())
}

fn receive_response(socket: &Socket) -> io::Result<Vec<Box<InetResponse>>> {
    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    let mut responses: Vec<Box<InetResponse>> = Vec::new();
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    responses.push(response);
                }
                NetlinkPayload::Done => {
                    return Ok(responses);
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
    Ok(responses)
}

fn main() -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let requests = [
        (AF_INET, IPPROTO_TCP),
        (AF_INET, IPPROTO_UDP)
    ];

    for tuple in requests {
        send_request(&mut socket, tuple.0, tuple.1)?;
        match receive_response(&socket) {
            Ok(resp) => {
                process_netlink_responses(tuple.0, tuple.1, resp);
            }
            Err(e) => return Err(e)
        }
    }
    Ok(())
}

