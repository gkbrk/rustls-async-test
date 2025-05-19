use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    sync::atomic::AtomicU64,
};

use crate::{ArcFd, DSSResult, error, fd_check_nonblocking, info, leo_async};

pub(crate) static RECEIVED_EVENTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static CLICKHOUSE_WRITTEN_EVENTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static THREADPOOL_COMPLETED_TASKS: AtomicU64 = AtomicU64::new(0);

pub(crate) trait AtomicU64Metric {
    fn get(&self) -> u64;
    fn set(&self, n: u64);
    fn inc(&self);
    fn inc_by(&self, n: u64);
}

impl AtomicU64Metric for AtomicU64 {
    fn get(&self) -> u64 {
        self.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set(&self, n: u64) {
        self.store(n, std::sync::atomic::Ordering::Relaxed)
    }

    fn inc(&self) {
        self.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn inc_by(&self, n: u64) {
        self.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }
}

fn fd_make_nonblocking(fd: &ArcFd) -> DSSResult<()> {
    let fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        let errno = nix::errno::Errno::last();
        return Err(format!("fcntl failed: {}", errno).into());
    }

    let flags = flags | libc::O_NONBLOCK;
    let res = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if res == -1 {
        let errno = nix::errno::Errno::last();
        return Err(format!("fcntl failed: {}", errno).into());
    }

    Ok(())
}

struct AsyncBufReader<T: leo_async::AsyncRead> {
    inner: T,
    buf: VecDeque<u8>,
}

impl<T: leo_async::AsyncRead> AsyncBufReader<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            buf: VecDeque::new(),
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> DSSResult<usize> {
        match self.buf.read(buf) {
            Ok(0) | Err(_) => {
                let mut read_buf = [0; 4096];
                let n = self.inner.read(&mut read_buf).await?;
                let y = self.buf.write(&read_buf[..n])?;
                match self.buf.read(buf) {
                    Ok(0) => Ok(0),
                    Ok(n) => Ok(n),
                    Err(_) => Err("read failed".into()),
                }
            }
            Ok(n) => Ok(n),
        }
    }

    async fn read_line(&mut self, line: &mut String) -> DSSResult<()> {
        loop {
            let mut buf = [0; 1];
            self.read(&mut buf).await?;
            if buf[0] == b'\n' {
                break;
            }
            line.push(buf[0] as char);
        }
        Ok(())
    }

    async fn read_line_alloc(&mut self) -> DSSResult<String> {
        let mut line = String::new();
        self.read_line(&mut line).await?;
        Ok(line)
    }
}

struct AsyncBufWriter<T: leo_async::AsyncWrite> {
    inner: T,
    buf: VecDeque<u8>,
}

impl<T: leo_async::AsyncWrite> Write for AsyncBufWriter<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("You can't flush an AsyncBufWriter with the sync interface");
    }
}

impl<T: leo_async::AsyncWrite> AsyncBufWriter<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            buf: VecDeque::new(),
        }
    }

    fn write(&mut self, buf: &[u8]) -> DSSResult<usize> {
        self.buf.write(buf)?;
        Ok(buf.len())
    }

    async fn flush(&mut self) -> DSSResult<()> {
        while !self.buf.is_empty() {
            let mut buf = [0; 4096];
            let n = self.buf.read(&mut buf)?;
            let written = self.inner.write(&buf[..n]).await?;

            if written < n {
                for i in (0..n - written).rev() {
                    self.buf.push_front(buf[written + i]);
                }
            }
        }
        Ok(())
    }
}

async fn handle_connection(fd: leo_async::ArcFd) -> DSSResult<()> {
    let read_fd = fd.clone();
    let write_fd = fd.dup()?;

    let mut reader = AsyncBufReader::new(read_fd);
    let mut writer = AsyncBufWriter::new(write_fd);

    let req_line = reader.read_line_alloc().await?;
    let req_line = req_line.trim();
    let (method, path) = {
        let parts = req_line.split_whitespace().collect::<Vec<_>>();
        (*parts.get(0).unwrap_or(&""), *parts.get(1).unwrap_or(&""))
    };

    info!("method: {}, path: {}", method, path);

    match (method, path) {
        ("GET", "/metrics") => {
            write!(&mut writer, "HTTP/1.1 200 OK\r\n")?;
            write!(&mut writer, "Connection: close\r\n")?;
            write!(&mut writer, "Content-Type: text/plain\r\n")?;
            write!(&mut writer, "\r\n")?;

            // Write metrics
            writeln!(&mut writer, "received_events {}", RECEIVED_EVENTS.get())?;
            writeln!(
                &mut writer,
                "threadpool_completed_tasks {}",
                THREADPOOL_COMPLETED_TASKS.get()
            )?;
            writeln!(
                &mut writer,
                "clickhouse_written_events {}",
                CLICKHOUSE_WRITTEN_EVENTS.get()
            )?;
            writer.flush().await?;
        }
        _ => {
            write!(&mut writer, "HTTP/1.1 404 Not Found\r\n")?;
            write!(&mut writer, "Connection: close\r\n")?;
            write!(&mut writer, "\r\n")?;
            writer.flush().await?;
        }
    }

    Ok(())
}

pub(crate) async fn metrics_server() -> DSSResult<()> {
    let socket = leo_async::socket::socket()?;
    fd_make_nonblocking(&socket)?;

    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::ReuseAddr, &true)?;

    let bind_addr = nix::sys::socket::SockaddrIn::new(127, 0, 0, 1, 7676);
    nix::sys::socket::bind(socket.as_raw_fd(), &bind_addr)?;
    nix::sys::socket::listen(&socket, nix::sys::socket::Backlog::new(1024)?)?;

    loop {
        if let Err(x) = leo_async::fd_wait_readable(&socket).await {
            error!("fd_wait_readable failed: {}", x);
            continue;
        }
        match nix::sys::socket::accept(socket.as_raw_fd()) {
            Ok(raw_fd) => {
                let fd = leo_async::ArcFd::from_raw_fd(raw_fd);
                fd_make_nonblocking(&fd)?;

                let req_handler = handle_connection(fd);
                let req_handler = std::boxed::Box::pin(req_handler);
                let req_handler =
                    leo_async::timeout_future(req_handler, std::time::Duration::from_secs(5));
                leo_async::spawn(req_handler);
            }
            Err(x) => {
                error!("accept failed: {}", x);
                continue;
            }
        }
    }

    Ok(())
}
