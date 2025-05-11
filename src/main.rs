use std::{
    io::{Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::Arc,
    time::Duration,
};

use leo_async::{ArcFd, DSSResult, fd_wait_readable, fd_wait_writable};

mod leo_async;
mod log;

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
    let sock = leo_async::socket::socket()?;
    fd_make_nonblocking(&sock)?;

    leo_async::socket::connect(&sock, addr).await?;
    fd_make_nonblocking(&sock)?;

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
    client: rustls::ClientConnection,
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

        let read_sock = sock.dup()?;
        fd_make_nonblocking(&read_sock)?;

        let write_sock = sock.dup()?;
        fd_make_nonblocking(&write_sock)?;

        Ok(Self {
            client,
            read_sock,
            write_sock,
        })
    }

    async fn run_iter(&mut self) -> DSSResult<(bool, bool)> {
        let read_sock = self.read_sock.clone();
        let write_sock = self.write_sock.clone();

        match (self.client.wants_read(), self.client.wants_write()) {
            (false, false) => return Ok((false, false)),
            (true, false) => {
                fd_wait_readable(&read_sock).await?;
            }
            (false, true) => {
                fd_wait_writable(&write_sock).await?;
            }
            (true, true) => {
                let read_fut = fd_wait_readable(&read_sock);
                let write_fut = fd_wait_writable(&write_sock);
                leo_async::select2_noresult(read_fut, write_fut).await;
            }
        };

        if self.client.wants_read() && leo_async::fd_readable(&read_sock)? {
            let mut buf = [0; 4096];
            let n = leo_async::read_fd(&read_sock, &mut buf).await?;
            if n == 0 {
                return Err("Read returned zero bytes".into());
            }

            self.client.read_tls(&mut std::io::Cursor::new(&buf[..n]))?;
            self.client.process_new_packets()?;
        }

        if self.client.wants_write() && leo_async::fd_writable(&write_sock)? {
            let mut buf = [0u8; 4096];
            let mut cursor = std::io::Cursor::new(&mut buf[..]);

            self.client.write_tls(&mut cursor)?;

            let buf = {
                let pos = cursor.position();
                let (buf, _) = buf.split_at(pos as usize);
                buf
            };

            writeall(&write_sock, buf).await?;
        }

        Ok((self.client.wants_read(), self.client.wants_write()))
    }

    async fn read(&mut self, buf: &mut [u8]) -> DSSResult<usize> {
        loop {
            match self.client.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // If we would block, run the TLS iteration
                    _ = self.run_iter().await?;
                }
                Err(e) => return Err(e.to_string().into()),
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> DSSResult<usize> {
        let written = self.client.writer().write(buf)?;

        // Do TLS writes until we don't want to write anymore

        loop {
            let (_wants_read, wants_write) = self.run_iter().await?;

            if !wants_write {
                break;
            }
        }

        Ok(written)
    }
}

async fn tls_test() -> DSSResult<()> {
    let hostname = "www.gkbrk.com";

    // Find first IPv4 address for the hostname
    let addr = {
        let mut addresses = ToSocketAddrs::to_socket_addrs(&(hostname, 443))?;
        addresses
            .find(|x| x.is_ipv4())
            .ok_or("No IPv4 address found")?
    };

    let mut client = TlsClient::connect(hostname, addr).await?;

    client.write(b"GET /robots.txt HTTP/1.0\r\n").await?;
    client
        .write(format!("Host: {}\r\n", hostname).as_bytes())
        .await?;
    client.write(b"Connection: close\r\n").await?;
    client.write(b"\r\n").await?;
    println!("Request sent");

    // Read and print the response until we get EOF
    let mut buf = [0; 4096];
    loop {
        let n = client.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        std::io::stdout().write_all(&buf[..n])?;
    }
    std::io::stdout().flush()?;

    println!("TLS socket closed");

    Ok(())
}

async fn async_main() -> DSSResult<()> {
    let tls_res = tls_test();
    let tls_res = std::pin::pin!(tls_res);
    match leo_async::timeout_future(tls_res, Duration::from_secs(5)).await {
        Ok(Ok(_)) => println!("TLS test completed successfully"),
        Ok(Err(e)) => println!("TLS test failed: {}", e),
        Err(_) => println!("TLS test timed out"),
    }

    Ok(())
}

fn main() {
    leo_async::run_main(async_main()).unwrap();
}
