use std::{
    io::{Read, Write},
    net::ToSocketAddrs,
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

async fn tls_test() -> DSSResult<()> {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let rc_config = Arc::new(config);
    let hostname = "www.gkbrk.com";
    let mut client = rustls::ClientConnection::new(rc_config, hostname.try_into()?)?;

    let addr = {
        let addresses = ToSocketAddrs::to_socket_addrs(&(hostname, 443))?;
        addresses
            .filter(|x| x.is_ipv4())
            .next()
            .ok_or("No IPv4 address found")?
    };

    let sock = connect(&addr).await?;

    let read_sock = sock.dup()?;
    fd_make_nonblocking(&read_sock)?;

    let write_sock = sock.dup()?;
    fd_make_nonblocking(&write_sock)?;

    {
        let mut writer = client.writer();
        write!(&mut writer, "GET /robots.txt HTTP/1.0\r\n")?;
        write!(&mut writer, "Host: {}\r\n", hostname)?;
        write!(&mut writer, "Connection: close\r\n")?;
        write!(&mut writer, "\r\n")?;
    }

    loop {
        match (client.wants_read(), client.wants_write()) {
            (false, false) => break,
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

        if client.wants_read() && leo_async::fd_readable(&read_sock)? {
            let mut buf = [0; 4096];
            let n = leo_async::read_fd(&read_sock, &mut buf).await?;
            if n == 0 {
                break;
            }

            client.read_tls(&mut std::io::Cursor::new(&buf[..n]))?;
            client.process_new_packets()?;

            let mut plaintext = Vec::new();
            match client.reader().read_to_end(&mut plaintext) {
                Ok(x) => {
                    std::io::stdout().write(&plaintext)?;
                    std::io::stdout().write(b"\n")?;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    return Err(e.to_string().into());
                }
            }
        }

        if client.wants_write() && leo_async::fd_writable(&write_sock)? {
            let mut buf = [0u8; 4096];
            let mut cursor = std::io::Cursor::new(&mut buf[..]);
            client.write_tls(&mut cursor)?;

            let buf = {
                let pos = cursor.position();
                let (buf, _) = buf.split_at(pos as usize);
                buf
            };

            writeall(&write_sock, buf).await?;
        }
    }

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
