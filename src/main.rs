// SPDX-License-Identifier: MIT
use std::fmt::{Display, Formatter};
use std::io;
use libc;

use netlink_packet_sock_diag::{
    constants::*,
    inet::StateFlags as InetStateFlags,
    inet::{ExtensionFlags, InetRequest,InetResponse, SocketId},
    inet::nlas::Nla as InetNla,
    inet::nlas::TcpInfo,
    unix::StateFlags as UnixStateFlags,
    unix::{ShowFlags, UnixRequest, UnixResponse},
    unix::nlas::Nla as UnixNla,
    NetlinkHeader,
    NetlinkMessage,
    NetlinkPayload,
    SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

struct DiagReq {
    af: u8,
    proto: u8,
}

impl Display for DiagReq {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match (self.af, self.proto) {
            (AF_INET, IPPROTO_TCP) => write!(f, "tcp"),
            (AF_INET6, IPPROTO_TCP) => write!(f, "tcp6"),
            (AF_INET, IPPROTO_UDP) => write!(f, "udp"),
            (AF_INET6, IPPROTO_UDP) => write!(f, "udp6"),
            (AF_INET, IPPROTO_RAW) => write!(f, "raw"),
            (AF_INET6, IPPROTO_RAW) => write!(f, "raw6"),
            (AF_UNIX, 0) => write!(f, "unix"),
            _ => write!(f, "unknown")
        }
    }
}

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

fn process_inet_response(req_type: &DiagReq, response: InetResponse) {
    let src_addr = response.header.socket_id.source_address;
    let src_port = response.header.socket_id.source_port;
    let dst_addr = response.header.socket_id.destination_address;
    let dst_port = response.header.socket_id.destination_port;
    print!("{} {}:{}-{}:{}",
           req_type, src_addr, src_port, dst_addr, dst_port);

    let state = response.header.state;
    print!(" {}", socket_state(state));

    for nla in response.nlas {
        match nla {
            InetNla::TcpInfo(tcp) => {
                tcp_info_handler(tcp);
            }
            _ => continue,
        }
    }
}

fn process_unix_response(response: UnixResponse) {
    let kind = response.header.kind;
    match kind {
        SOCK_PACKET => print!("unix_seqpacket"),
        SOCK_STREAM => print!("unix_stream"),
        SOCK_DGRAM => print!("unix_dgram"),
        _ => return
    }

    let state = response.header.state;
    print!(" {}", socket_state(state));
    for nla in response.nlas {
        match nla {
            UnixNla::Name(name) => {
                print!(" path: {}", name);
            }
            _ => continue,
        }
    }
}

fn process_netlink_responses(req_type: &DiagReq, responses: Vec<SockDiagMessage>) {
    for response in responses {
        match response {
            SockDiagMessage::InetResponse(r) => process_inet_response(req_type, *r),
            SockDiagMessage::UnixResponse(r) => process_unix_response(*r),
            _ => continue
        }
        println!();
    }
}

fn send_request(socket: &mut Socket, req_type: &DiagReq) -> io::Result<()> {
    let request_payload = match req_type.af {
        AF_INET | AF_INET6 => {
            SockDiagMessage::InetRequest(InetRequest {
                family: req_type.af,
                protocol: req_type.proto,
                extensions: ExtensionFlags::all(),
                states: InetStateFlags::all(),
                socket_id: SocketId::new_v4(),
            })
        }
        AF_UNIX => {
            SockDiagMessage::UnixRequest(UnixRequest {
                state_flags: UnixStateFlags::all(),
                show_flags: ShowFlags::all(),
                inode: 0,
                cookie: [0; 8]
            })
        }
        _ => panic!("Unknown address family")
    };
    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            message_type: SOCK_DIAG_BY_FAMILY,
            ..Default::default()
        },
        payload: request_payload.into(),
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

fn receive_response(socket: &Socket) -> io::Result<Vec<SockDiagMessage>> {
    let mut peek_buf = vec![0];
    let mut offset = 0;
    let mut responses: Vec<SockDiagMessage> = Vec::new();
    while let Ok(size) = socket.recv(&mut &mut peek_buf[..], libc::MSG_PEEK | libc::MSG_TRUNC) {
        let mut receive_buffer = vec![0; size];
        socket.recv(&mut &mut receive_buffer[..], 0)?;
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    responses.push(SockDiagMessage::InetResponse(response));
                }
                NetlinkPayload::InnerMessage(SockDiagMessage::UnixResponse(response))=> {
                    responses.push(SockDiagMessage::UnixResponse(response));
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
        DiagReq{af: AF_INET, proto: IPPROTO_TCP},
        DiagReq{af: AF_INET6, proto: IPPROTO_TCP},
        DiagReq{af: AF_INET, proto: IPPROTO_UDP},
        DiagReq{af: AF_INET6, proto: IPPROTO_UDP},
        DiagReq{af: AF_INET, proto: IPPROTO_RAW},
        DiagReq{af: AF_INET6, proto: IPPROTO_RAW},
        DiagReq{af: AF_UNIX, proto: 0},
    ];

    for req_type in requests {
        send_request(&mut socket, &req_type)?;
        match receive_response(&socket) {
            Ok(resp) => {
                process_netlink_responses(&req_type, resp);
            }
            Err(e) => return Err(e)
        }
    }
    Ok(())
}
