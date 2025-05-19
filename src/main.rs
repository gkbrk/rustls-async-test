use std::{
    collections::VecDeque,
    io::{BufRead, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::Arc,
    vec,
};

use cowboy::*;

use json::JsonValue;
use leo_async::{ArcFd, DSSResult, fd_wait_readable, fd_wait_writable};
use metrics::{AtomicU64Metric, metrics_server};

mod cowboy;
mod dotenv;
mod leo_async;
mod log;
mod metrics;

impl Read for ArcFd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let raw_fd = self.as_raw_fd();
        match nix::unistd::read(self, buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "read would block",
            )),
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to read from fd {}: {}", raw_fd, e),
            )),
        }
    }
}

impl Write for ArcFd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let raw_fd = self.as_raw_fd();
        match nix::unistd::write(self, buf) {
            Ok(n) => Ok(n),
            Err(nix::errno::Errno::EAGAIN) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "write would block",
            )),
            Err(e) => Err(std::io::Error::other(format!(
                "Failed to write to fd {}: {}",
                raw_fd, e
            ))),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fd_check_nonblocking(fd: &ArcFd) -> DSSResult<()> {
    let fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err("fcntl failed".into());
    }

    assert!(flags & libc::O_NONBLOCK != 0, "fd is not nonblocking");

    Ok(())
}

fn fd_make_nonblocking(fd: &ArcFd) -> DSSResult<()> {
    let fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err("fcntl failed".into());
    }

    let flags = flags | libc::O_NONBLOCK;
    let res = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if res == -1 {
        return Err("fcntl failed".into());
    }

    Ok(())
}

async fn connect(addr: &std::net::SocketAddr) -> DSSResult<ArcFd> {
    let sock = match addr {
        SocketAddr::V4(_) => leo_async::socket::socket()?,
        SocketAddr::V6(_) => leo_async::socket::socket6()?,
    };
    fd_make_nonblocking(&sock)?;

    leo_async::socket::connect(&sock, addr).await?;

    Ok(sock)
}

async fn writeall(fd: &ArcFd, buf: &[u8]) -> DSSResult<()> {
    let mut remaining = buf;

    while !remaining.is_empty() {
        let n = leo_async::write_fd(fd, remaining).await?;
        if n == 0 {
            return Err("Write returned zero bytes".into());
        }
        remaining = &remaining[n..];
    }

    Ok(())
}

struct TlsClient {
    client: cowboy::Cowboy<rustls::ClientConnection>,
    read_sock: ArcFd,
    write_sock: ArcFd,
}

impl TlsClient {
    async fn connect(hostname: &str, addr: SocketAddr) -> DSSResult<Self> {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let rc_config = Arc::new(config);
        let client = rustls::ClientConnection::new(rc_config, hostname.to_string().try_into()?)?;

        let sock = connect(&addr).await?;

        Ok(Self {
            client: client.cowboy(),
            read_sock: sock.dup()?,
            write_sock: sock,
        })
    }

    async fn run_iter(&mut self) -> DSSResult<(bool, bool)> {
        leo_async::yield_now().await;

        match { (self.client.r().wants_read(), self.client.r().wants_write()) } {
            (false, false) => return Ok((false, false)),
            (true, false) => {
                fd_wait_readable(&self.read_sock).await?;
            }
            (false, true) => {
                fd_wait_writable(&self.write_sock).await?;
            }
            (true, true) => {
                let read_fut = fd_wait_readable(&self.read_sock);
                let write_fut = fd_wait_writable(&self.write_sock);
                leo_async::select2_noresult(read_fut, write_fut).await;
            }
        };

        leo_async::yield_now().await;

        if self.client.r().wants_read() {
            let readable = { leo_async::fd_readable(&self.read_sock)? };
            if readable {
                match { self.client.w().read_tls(&mut self.read_sock) } {
                    Ok(0) => {
                        // EOF
                        return Ok((false, false));
                    }
                    Ok(_x) => {
                        let c = self.client.clone();
                        leo_async::fn_thread_future(move || c.w().process_new_packets()).await?;
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            return Err(e.to_string().into());
                        }
                    }
                }
            }
        }

        leo_async::yield_now().await;

        if self.client.r().wants_write() {
            let writable = { leo_async::fd_writable(&self.write_sock)? };
            if writable {
                match self.client.w().write_tls(&mut self.write_sock) {
                    Ok(0) => {
                        // EOF
                        return Ok((false, false));
                    }
                    Ok(_x) => {
                        // Successfully wrote
                    }
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            return Err(e.to_string().into());
                        }
                    }
                }
            }
        }

        leo_async::yield_now().await;

        Ok((self.client.r().wants_read(), self.client.r().wants_write()))
    }

    async fn read(&mut self, buf: &mut [u8]) -> DSSResult<usize> {
        loop {
            match { self.client.w().reader().read(buf) } {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // If we would block, run the TLS iteration
                    _ = self.run_iter().await?;
                }
                Err(e) => return Err(e.to_string().into()),
            }
        }
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> DSSResult<()> {
        let mut remaining = buf;

        while !remaining.is_empty() {
            let n = self.read(remaining).await?;
            if n == 0 {
                return Err("Read returned zero bytes".into());
            }
            remaining = &mut remaining[n..];
        }

        Ok(())
    }

    async fn read_line(&mut self, buf: &mut String) -> DSSResult<usize> {
        loop {
            match { self.client.w().reader().read_line(buf) } {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    _ = self.run_iter().await?;
                }
                Err(e) => return Err(e.to_string().into()),
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> DSSResult<usize> {
        let written = self.client.w().writer().write(buf)?;

        // Do TLS writes until we don't want to write anymore

        loop {
            let (_wants_read, wants_write) = self.run_iter().await?;

            if !wants_write {
                break;
            }
        }

        Ok(written)
    }

    async fn write_all(&mut self, buf: &[u8]) -> DSSResult<()> {
        let mut idx = 0;

        while idx < buf.len() {
            let n = self.write(&buf[idx..]).await?;
            idx += n;
        }

        Ok(())
    }
}

async fn websocket_handshake(
    sock: &mut TlsClient,
    hostname: &str,
    endpoint: &str,
) -> DSSResult<()> {
    sock.write_all(format!("GET {} HTTP/1.1\r\n", endpoint).as_bytes())
        .await?;
    sock.write_all(format!("Host: {}\r\n", hostname).as_bytes())
        .await?;
    sock.write_all(b"Upgrade: websocket\r\n").await?;
    sock.write_all(b"Connection: Upgrade\r\n").await?;
    sock.write_all(b"Sec-WebSocket-Key: eWVsbG93IHN1Ym1hcmluZQ==\r\n")
        .await?;
    sock.write_all(b"Sec-WebSocket-Version: 13\r\n").await?;
    sock.write_all(format!("Origin: https://{}\r\n", hostname).as_bytes())
        .await?;
    sock.write_all(b"\r\n").await?;

    async fn read_line(sock: &mut TlsClient) -> DSSResult<String> {
        let mut line = String::new();
        sock.read_line(&mut line).await?;
        Ok(line)
    }

    let response_line = read_line(sock).await?;
    let parts = response_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return Err("Invalid response line".into());
    }

    if parts[0] != "HTTP/1.1" {
        return Err("Invalid HTTP version".into());
    }

    if parts[1] != "101" {
        return Err(format!("Invalid response code: {}", parts[1]).into());
    }

    // Read until response is empty
    loop {
        let line = read_line(sock).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct WebsocketFrameHeader {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: u8,
    pub mask: bool,
    pub payload_len: u64,
    pub masking_key: [u8; 4],
}

impl WebsocketFrameHeader {
    pub async fn read_async(reader: &mut TlsClient) -> DSSResult<Self> {
        // 1. Read the first 2 bytes
        let mut header = [0u8; 2];
        reader.read_exact(&mut header).await?;

        let fin = (header[0] & 0b1000_0000) != 0;
        let rsv1 = (header[0] & 0b0100_0000) != 0;
        let rsv2 = (header[0] & 0b0010_0000) != 0;
        let rsv3 = (header[0] & 0b0001_0000) != 0;
        let opcode = header[0] & 0b0000_1111;

        let mask = (header[1] & 0b1000_0000) != 0;
        let mut payload_len = (header[1] & 0b0111_1111) as u64;

        // 2. Extended payload length
        if payload_len == 126 {
            let mut ext = [0u8; 2];
            reader.read_exact(&mut ext).await?;
            payload_len = u16::from_be_bytes(ext) as u64;
        } else if payload_len == 127 {
            let mut ext = [0u8; 8];
            reader.read_exact(&mut ext).await?;
            // Per RFC 6455, the most significant bit must be 0
            if ext[0] & 0b1000_0000 != 0 {
                return Err("Invalid WebSocket frame: 64-bit payload length MSB must be 0".into());
            }
            payload_len = u64::from_be_bytes(ext);
        }

        // 3. Masking key
        let masking_key = if mask {
            let mut key = [0u8; 4];
            reader.read_exact(&mut key).await?;
            key
        } else {
            [0u8; 4]
        };

        Ok(WebsocketFrameHeader {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            mask,
            payload_len,
            masking_key,
        })
    }
}

#[derive(Debug)]
enum WebsocketPacket {
    Text(String),
    Binary(Vec<u8>),
    ConnectionClose,
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    NothingToSeeHere,
}

async fn read_websocket_packet(sock: &mut TlsClient) -> DSSResult<WebsocketPacket> {
    let header = WebsocketFrameHeader::read_async(sock).await?;

    if header.payload_len > 32_768 {
        // Skip message without reading all of it into memory
        let mut left = header.payload_len;

        while left > 0 {
            let mut buf = vec![0u8; std::cmp::min(left.try_into()?, 4096)];
            sock.read_exact(&mut buf).await?;
            left -= buf.len() as u64;
        }

        return Ok(WebsocketPacket::NothingToSeeHere);
    }

    if !header.fin {
        return Err("Fragmented frames are not supported".into());
    }

    let mut payload = {
        let mut buf = vec![0u8; header.payload_len as usize];
        sock.read_exact(&mut buf).await?;
        buf
    };

    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= header.masking_key[i % 4];
    }

    let packet = match header.opcode {
        0x1 => WebsocketPacket::Text(String::from_utf8(payload)?),
        0x2 => WebsocketPacket::Binary(payload),
        0x8 => WebsocketPacket::ConnectionClose,
        0x9 => WebsocketPacket::Ping(payload),
        0xA => WebsocketPacket::Pong(payload),
        _ => return Err("Unknown opcode".into()),
    };

    Ok(packet)
}

async fn write_websocket_packet(sock: &mut TlsClient, packet: WebsocketPacket) -> DSSResult<()> {
    let (opcode, mut payload) = match packet {
        WebsocketPacket::Text(text) => (0x1, text.into_bytes()),
        WebsocketPacket::Binary(data) => (0x2, data),
        WebsocketPacket::ConnectionClose => (0x8, vec![]),
        WebsocketPacket::Ping(data) => (0x9, data),
        WebsocketPacket::Pong(data) => (0xA, data),
        WebsocketPacket::NothingToSeeHere => return Ok(()),
    };

    let payload_len = payload.len() as u64;
    let mask_bit = 0b1000_0000; // mask bit set

    let mut header = Vec::with_capacity(14); // enough for header, key, and small payload

    header.push(0b1000_0000 | (opcode & 0x0F)); // FIN + opcode

    // Encode length and mask bit
    if payload_len < 126 {
        header.push(mask_bit | (payload_len as u8));
    } else if payload_len <= 65535 {
        header.push(mask_bit | 126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(mask_bit | 127);
        header.extend_from_slice(&payload_len.to_be_bytes());
    }

    // Generate mask and append to header
    let mask: [u8; 4] = *b"Leo_";
    header.extend_from_slice(&mask);

    // Mask the payload in-place
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }

    // Send header and masked payload
    sock.write_all(&header).await?;
    sock.write_all(&payload).await?;

    Ok(())
}

async fn websocket_test(
    event_sender: leo_async::mpsc::Sender<JsonValue>,
    hostname: String,
    port: u16,
    endpoint: String,
) -> DSSResult<()> {
    let addresses = {
        let hostname = hostname.clone();
        leo_async::fn_thread_future(move || -> DSSResult<Vec<SocketAddr>> {
            match ToSocketAddrs::to_socket_addrs(&(hostname, port)) {
                Ok(x) => Ok(x.collect()),
                Err(e) => Err(e.to_string().into()),
            }
        })
        .await?
    };

    let addr = *addresses.first().ok_or("No address found")?;

    let mut client = TlsClient::connect(&hostname, addr).await?;

    // Do handshake
    websocket_handshake(&mut client, hostname.as_str(), endpoint.as_str()).await?;
    info!("WebSocket handshake completed");

    write_websocket_packet(&mut client, WebsocketPacket::Ping(b"hey there :)".to_vec())).await?;

    write_websocket_packet(
        &mut client,
        WebsocketPacket::Text("[\"REQ\",\"a\",{\"limit\":0}]".to_string()),
    )
    .await?;

    loop {
        leo_async::yield_now().await;
        let msg = read_websocket_packet(&mut client).await?;
        match msg {
            WebsocketPacket::Ping(data) => {
                write_websocket_packet(&mut client, WebsocketPacket::Pong(data)).await?;
            }
            WebsocketPacket::Text(str) => {
                let json = leo_async::fn_thread_future(move || -> DSSResult<JsonValue> {
                    let json = json::parse(&str)?;
                    Ok(json)
                })
                .await?;
                if json.is_array() && json.len() == 3 {
                    metrics::RECEIVED_EVENTS.inc();
                    let event = &json[2];
                    event_sender
                        .send(event.clone())
                        .map_err(|_| "".to_string())?;
                }
            }
            WebsocketPacket::ConnectionClose => {
                info!("Connection closed");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn tls_websocket_task(
    sender: leo_async::mpsc::Sender<JsonValue>,
    hostname: String,
    port: u16,
    endpoint: String,
) -> DSSResult<()> {
    loop {
        let result = websocket_test(sender.clone(), hostname.clone(), port, endpoint.clone()).await;
        match result {
            Ok(_) => {
                info!("Connection closed but no error?");
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
            }
        }
        leo_async::sleep_seconds(15).await;
    }
}

async fn message_to_ch_task(recv: leo_async::mpsc::Receiver<json::JsonValue>) -> DSSResult<()> {
    let mut event_buffer = VecDeque::new();

    let conf = dotenv::load_dotenv(".env")?;
    let host = conf
        .get("CLICKHOUSE_HOST")
        .ok_or("No host in config")?
        .clone();
    let port_str = conf
        .get("CLICKHOUSE_PORT")
        .ok_or("No port in config")?
        .clone();
    let port = port_str.parse::<u16>()?;
    let user = conf
        .get("CLICKHOUSE_USER")
        .ok_or("No user in config")?
        .clone();
    let password = conf
        .get("CLICKHOUSE_PASSWORD")
        .ok_or("No password in config")?
        .clone();
    let database = conf
        .get("CLICKHOUSE_DATABASE")
        .ok_or("No database in config")?
        .clone();

    let ch_addr = ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))?
        .next()
        .ok_or("No address found for ClickHouse")?;

    loop {
        let received_message = recv.recv().await;
        match received_message {
            Some(msg) => {
                event_buffer.push_back(msg);

                let chunk_size = 512;

                if event_buffer.len() == chunk_size {
                    metrics::CLICKHOUSE_WRITTEN_EVENTS.inc_by(chunk_size as u64);

                    let sock = match ch_addr {
                        SocketAddr::V4(_) => leo_async::socket::socket()?,
                        SocketAddr::V6(_) => leo_async::socket::socket6()?,
                    };

                    fd_make_nonblocking(&sock)?;
                    leo_async::socket::connect(&sock, &ch_addr).await?;

                    let mut buf: Vec<u8> = Vec::new();

                    writeln!(
                        &mut buf,
                        "insert into event settings async_insert = 1, wait_for_async_insert = 0 format JSONEachRow",
                    )?;

                    for event in &event_buffer {
                        writeln!(&mut buf, "{}", event.dump())?;
                    }

                    event_buffer.clear();

                    writeall(
                        &sock,
                        format!(
                            "POST /?user={}&password={}&database={} HTTP/1.1\r\n",
                            user, password, database
                        )
                        .as_bytes(),
                    )
                    .await?;
                    writeall(&sock, b"Connection: close\r\n").await?;
                    writeall(
                        &sock,
                        format!("Content-Length: {}\r\n", buf.len()).as_bytes(),
                    )
                    .await?;
                    writeall(&sock, b"\r\n").await?;

                    writeall(&sock, &buf).await?;
                }
            }
            None => {
                error!("Error receiving message");
                break;
            }
        }
    }

    Ok(())
}

async fn async_main() -> DSSResult<()> {
    leo_async::spawn(async {
        metrics_server().await.unwrap();
    });

    let (event_sender, event_receiver) = leo_async::mpsc::channel();

    let relay_list = std::fs::read_to_string("relay_list.txt")?;
    let relays = relay_list.lines().collect::<Vec<&str>>();

    for relay in relays {
        let url = match url::Url::parse(relay) {
            Ok(url) => url,
            Err(e) => {
                error!("Error parsing URL: {} ({})", e, relay);
                continue;
            }
        };

        if url.scheme() != "wss" {
            continue;
        }

        let hostname = url.host_str().ok_or("No hostname in URL")?;
        let port = url.port().unwrap_or(443);

        let endpoint = url.path();

        leo_async::spawn(tls_websocket_task(
            event_sender.clone(),
            hostname.to_string(),
            port,
            endpoint.to_string(),
        ));
    }

    message_to_ch_task(event_receiver).await?;

    Ok(())
}

fn main() {
    leo_async::run_main(async_main()).unwrap();
}
