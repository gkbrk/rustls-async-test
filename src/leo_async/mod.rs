use std::{
    collections::HashMap,
    future::Future,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, OnceLock, RwLock},
    task::{Poll, Waker},
    time::Instant,
};

use crossbeam::queue::SegQueue;

use crate::{error, info, trace};

struct InternalPollFn<F> {
    f: F,
}

impl<T, F> Future for InternalPollFn<F>
where
    F: FnMut(&mut std::task::Context<'_>) -> Poll<T>,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<T> {
        let start = std::time::Instant::now();
        let res = (unsafe { &mut self.get_unchecked_mut().f })(cx);
        let dur = start.elapsed();

        if dur.as_micros() > 100 {
            crate::warn!("internal_poll_fn task took {:?}", dur);
        }

        res
    }
}

fn internal_poll_fn<T, F>(f: F) -> InternalPollFn<F>
where
    F: FnMut(&mut std::task::Context<'_>) -> Poll<T>,
{
    InternalPollFn { f }
}

fn make_threadpool(num_threads: usize) -> crossbeam::channel::Sender<Box<dyn FnOnce() + Send + 'static>>
{
    let (tx, rx) = crossbeam::channel::unbounded();

    for _ in 0..num_threads {
        let rx: crossbeam::channel::Receiver<Box<dyn FnOnce() + Send + 'static>> = rx.clone();
        std::thread::spawn(move || {
            while let Ok(f) = rx.recv() {
                f();
            }
        });
    }

    return tx;
}

pub(crate) fn noisytimer(s: &'_ str, microseconds: u64) -> impl Drop + '_ {
    struct X<'a>(&'a str, std::time::Instant, std::time::Duration);

    impl Drop for X<'_> {
        fn drop(&mut self) {
            let now = std::time::Instant::now();
            let dur = now - self.1;

            if dur > self.2 {
                crate::warn!("NoisyTimer: {} took too long ({:?})", self.0, dur);
            } else {
                crate::trace!("NoisyTimer: {} took {:?}", self.0, dur);
            }
        }
    }

    X(
        s,
        std::time::Instant::now(),
        std::time::Duration::from_micros(microseconds),
    )
}

pub(crate) struct ArcFd {
    fd: Arc<OwnedFd>,
}

impl ArcFd {
    pub(crate) fn from_owned_fd(fd: OwnedFd) -> Self {
        ArcFd { fd: Arc::new(fd) }
    }

    pub(crate) fn dup(&self) -> DSSResult<Self> {
        let fd = self.as_raw_fd();
        let res = unsafe { libc::dup(fd) };
        match res {
            -1 => Err("dup failed".into()),
            fd => Ok(ArcFd::from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })),
        }
    }
}

impl PartialEq for ArcFd {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw_fd() == other.as_raw_fd()
    }
}

impl Eq for ArcFd {}

impl std::hash::Hash for ArcFd {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_raw_fd().hash(state);
    }
}

impl AsRawFd for ArcFd {
    fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl AsFd for ArcFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.fd.as_raw_fd()) }
    }
}

impl Clone for ArcFd {
    fn clone(&self) -> Self {
        ArcFd {
            fd: self.fd.clone(),
        }
    }
}

pub(super) type DSSResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Task {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    sender: Arc<SegQueue<Arc<Task>>>,
}

impl std::task::Wake for Task {
    fn wake(self: Arc<Self>) {
        let sender = self.sender.clone();
        sender.push(self);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.sender.push(self.clone());
    }
}

static EXIT_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static THREADPOOL_SENDER: OnceLock<crossbeam::channel::Sender<Box<dyn FnOnce() + Send + 'static>>> = OnceLock::new();

static TASK_SENDER: OnceLock<Arc<SegQueue<Arc<Task>>>> = OnceLock::new();

static EPOLL_REGISTER: LazyLock<mpsc::Sender<(ArcFd, epoll::PollType, Waker)>> =
    LazyLock::new(epoll::epoll_task);

static SLEEP_REGISTER: LazyLock<std::sync::mpsc::Sender<(Instant, Box<Waker>)>> =
    LazyLock::new(|| {
        let (sender, receiver) = std::sync::mpsc::channel();

        std::thread::Builder::new()
            .name("sleep-task".to_string())
            .spawn(|| sleep::sleep_task(receiver))
            .expect("Failed to spawn sleep task");

        sender
    });

pub(super) fn read_fd<'a>(
    fd: &'a ArcFd,
    buf: &'a mut [u8],
) -> impl Future<Output = DSSResult<usize>> + 'a {
    internal_poll_fn(move |cx| match nix::unistd::read(fd, buf) {
        Ok(n) => Poll::Ready(Ok(n)),
        Err(nix::errno::Errno::EAGAIN) => {
            EPOLL_REGISTER
                .send((fd.clone(), epoll::PollType::Read, cx.waker().clone()))
                .unwrap();
            Poll::Pending
        }
        Err(e) => Poll::Ready(Err(e.into())),
    })
}

pub(super) fn write_fd<'a>(
    fd: &'a ArcFd,
    buf: &'a [u8],
) -> impl Future<Output = DSSResult<usize>> + 'a {
    internal_poll_fn(move |cx| match nix::unistd::write(fd, buf) {
        Ok(n) => Poll::Ready(Ok(n)),
        Err(nix::errno::Errno::EAGAIN) => {
            EPOLL_REGISTER
                .send((fd.clone(), epoll::PollType::Write, cx.waker().clone()))
                .unwrap();
            Poll::Pending
        }
        Err(e) => Poll::Ready(Err(e.into())),
    })
}

pub(super) fn fd_readable(fd: &ArcFd) -> DSSResult<bool> {
    let mut fds = [nix::poll::PollFd::new(
        fd.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    {
        nix::poll::poll(&mut fds, nix::poll::PollTimeout::ZERO)?;
    }

    Ok(fds[0]
        .revents()
        .ok_or(":(")?
        .contains(nix::poll::PollFlags::POLLIN))
}

pub(super) fn fd_writable(fd: &ArcFd) -> DSSResult<bool> {
    let mut fds = [nix::poll::PollFd::new(
        fd.as_fd(),
        nix::poll::PollFlags::POLLOUT,
    )];
    {
        nix::poll::poll(&mut fds, nix::poll::PollTimeout::ZERO)?;
    }

    Ok(fds[0]
        .revents()
        .ok_or(":(")?
        .contains(nix::poll::PollFlags::POLLOUT))
}

pub(super) fn fd_wait_readable(fd: &ArcFd) -> impl Future<Output = DSSResult<()>> + '_ {
    internal_poll_fn(move |cx| {
        if { fd_readable(fd)? } {
            return Poll::Ready(Ok(()));
        }

        // Register interest in the file descriptor being readable
        EPOLL_REGISTER
            .send((fd.clone(), epoll::PollType::Read, cx.waker().clone()))
            .unwrap();

        // Return pending, the waker will be called when the fd is readable
        Poll::Pending
    })
}

pub(super) fn fd_wait_writable(fd: &ArcFd) -> impl Future<Output = DSSResult<()>> + '_ {
    internal_poll_fn(move |cx| {
        if { fd_writable(fd)? } {
            return Poll::Ready(Ok(()));
        }

        // Register interest in the file descriptor being writable
        EPOLL_REGISTER
            .send((fd.clone(), epoll::PollType::Write, cx.waker().clone()))
            .unwrap();

        // Return pending, the waker will be called when the fd is writable
        Poll::Pending
    })
}

pub(super) fn spawn<F, T>(future: F)
where
    F: Future<Output = T> + Send + 'static,
{
    let sender = TASK_SENDER.get().unwrap();

    let future = async {
        _ = future.await;
    };

    let task = Arc::new(Task {
        future: Mutex::new(Some(Box::pin(future))),
        sender: sender.clone(),
    });

    sender.push(task);
}

pub(super) fn run_main<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static + std::fmt::Debug,
{
    THREADPOOL_SENDER.set(make_threadpool(32)).unwrap();

    let task_receiver = {
        let q = SegQueue::new();
        let q = Arc::new(q);
        TASK_SENDER.set(q.clone()).unwrap();
        q
    };
    let t = std::thread::spawn(|| run_forever(task_receiver));

    let (result_sender, result_receiver) = std::sync::mpsc::channel();

    spawn(async move {
        let res = future.await;
        result_sender.send(res).unwrap();
    });

    let res = result_receiver.recv().unwrap();

    // Got a result, let's exit
    EXIT_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);

    t.join().unwrap();
    res
}

pub(super) fn fn_thread_future<T>(
    f: impl FnOnce() -> T + Send + Sync + 'static,
) -> impl Future<Output = T>
where
    T: Send + 'static,
{
    let result = Arc::new(Mutex::new(None));
    let waker = Arc::new(Mutex::new(None));

    let pollfn = {
        let result = result.clone();
        let waker = waker.clone();
        internal_poll_fn(move |ctx| {
            waker.lock().unwrap().replace(ctx.waker().clone());

            match result.lock().unwrap().take() {
                Some(res) => Poll::Ready(res),
                None => Poll::Pending,
            }
        })
    };

    let sender = THREADPOOL_SENDER.get().expect("Threadpool not initialized");
    sender.send(Box::new(move || {
        let res = f();
        result.lock().unwrap().replace(res);

        loop {
            match waker.lock().unwrap().take() {
                Some(w) => {
                    w.wake();
                    break;
                }
                None => std::thread::yield_now(),
            }
        }
    })).expect("Failed to send task to threadpool");

    pollfn
}

fn run_forever(task_receiver: Arc<SegQueue<Arc<Task>>>) {
    loop {
        let mut task_set = HashMap::new();

        loop {
            if let Some(task) = task_receiver.pop() {
                task_set.insert(Arc::as_ptr(&task), task);
            } else {
                if task_set.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                break;
            }
        }

        crate::trace!("Running {} tasks", task_set.len());

        for (_, task) in task_set.drain() {
            let _timer = noisytimer("future poll", 500);
            let waker = std::task::Waker::from(task.clone());
            let context = &mut std::task::Context::from_waker(&waker);

            let mut future_slot = task.future.lock().unwrap();

            if let Some(mut future) = future_slot.take() {
                if future.as_mut().poll(context).is_pending() {
                    // Not done, put it back
                    *future_slot = Some(future);
                }
            } else {
                // This should never happen
                error!("Task with no future");
            }
        }
    }
}

pub(super) fn sleep_seconds(seconds: impl Into<f64>) -> impl Future<Output = ()> {
    let seconds = seconds.into();
    let target = std::time::Instant::now() + std::time::Duration::from_secs_f64(seconds);

    internal_poll_fn(move |cx| {
        let now = std::time::Instant::now();

        if now >= target {
            Poll::Ready(())
        } else {
            // Register a sleep waker
            SLEEP_REGISTER
                .send((target, Box::new(cx.waker().clone())))
                .unwrap();
            Poll::Pending
        }
    })
}

fn get_errno() -> i32 {
    unsafe { (*libc::__errno_location()) as i32 }
}

pub(super) mod socket {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use crate::fd_wait_writable;

    use super::{ArcFd, DSSResult, get_errno};

    pub fn socket() -> DSSResult<ArcFd> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };

        match fd {
            -1 => Err("socket failed".into()),
            fd => Ok(ArcFd::from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })),
        }
    }

    pub fn socket6() -> DSSResult<ArcFd> {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };

        match fd {
            -1 => Err("socket failed".into()),
            fd => Ok(ArcFd::from_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })),
        }
    }

    pub async fn connect<'a>(sock: &'a ArcFd, addr: &std::net::SocketAddr) -> DSSResult<()> {
        let mut sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };

        let mut sockaddr6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as u16,
            sin6_port: addr.port().to_be(),
            sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
            sin6_flowinfo: 0,
            sin6_scope_id: 0,
        };

        match addr {
            std::net::SocketAddr::V4(x) => {
                sockaddr.sin_addr.s_addr = x.ip().to_bits().to_be();
            }
            std::net::SocketAddr::V6(x) => {
                sockaddr6.sin6_addr.s6_addr = x.ip().octets();
            }
        }

        let size = match addr {
            std::net::SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>() as u32,
            std::net::SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>() as u32,
        };

        let addr = match addr {
            std::net::SocketAddr::V4(_) => &sockaddr as *const _ as *const libc::sockaddr,
            std::net::SocketAddr::V6(_) => &sockaddr6 as *const _ as *const libc::sockaddr,
        };

        let res = unsafe { libc::connect(sock.as_raw_fd(), addr, size) };

        match res {
            0 => return Ok(()),
            -1 => match get_errno() {
                libc::EINPROGRESS | libc::EALREADY => {
                    fd_wait_writable(sock).await?;
                    return Ok(());
                }
                libc::EISCONN => return Ok(()),
                _ => return Err(format!("connect failed: {}", get_errno()).into()),
            },
            _ => unreachable!(),
        }
    }

    pub fn set_nodelay(fd: &ArcFd) -> DSSResult<()> {
        let fd = fd.as_raw_fd();
        let flag = 1;

        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_NODELAY,
                &flag as *const _ as *const _,
                4,
            )
        };

        match res {
            0 => Ok(()),
            -1 => Err("setsockopt failed".into()),
            _ => unreachable!(),
        }
    }
}

pub(super) mod mpsc {
    use std::{
        collections::VecDeque,
        future::Future,
        sync::{Arc, Mutex},
        task::{Poll, Waker},
    };

    use super::internal_poll_fn;

    struct Inner<T> {
        q: VecDeque<T>,
        waker: Option<Waker>,
        sender_count: usize,
        receiver_there: bool,
    }

    pub struct Receiver<T> {
        inner: Arc<Mutex<Inner<T>>>,
    }

    pub struct Sender<T> {
        inner: Arc<Mutex<Inner<T>>>,
    }

    impl<T> Sender<T> {
        pub fn send(&self, value: T) -> Result<(), ()> {
            let mut inner = self.inner.lock().unwrap();

            if inner.receiver_there {
                inner.q.push_back(value);
                if let Some(waker) = inner.waker.take() {
                    waker.wake();
                }
                Ok(())
            } else {
                Err(())
            }
        }
    }

    impl<T> Drop for Sender<T> {
        fn drop(&mut self) {
            let mut inner = self.inner.lock().unwrap();

            match inner.sender_count {
                0 => panic!("Dropped below zero"),
                1 => {
                    if let Some(waker) = inner.waker.take() {
                        waker.wake();
                    }
                }
                _ => {}
            }

            inner.sender_count -= 1;
        }
    }

    impl<T> Clone for Sender<T> {
        fn clone(&self) -> Self {
            let mut inner = self.inner.lock().unwrap();
            inner.sender_count += 1;

            Sender {
                inner: self.inner.clone(),
            }
        }
    }

    impl<T> Receiver<T> {
        pub fn recv(&self) -> impl Future<Output = Option<T>> + '_ {
            internal_poll_fn(|ctx| {
                let mut inner = self.inner.lock().unwrap();

                if let Some(value) = inner.q.pop_front() {
                    Poll::Ready(Some(value))
                } else if inner.sender_count > 0 {
                    inner.waker = Some(ctx.waker().clone());
                    Poll::Pending
                } else {
                    Poll::Ready(None)
                }
            })
        }
    }

    impl<T> Drop for Receiver<T> {
        fn drop(&mut self) {
            let mut inner = self.inner.lock().unwrap();
            inner.receiver_there = false;
        }
    }

    pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(Mutex::new(Inner {
            q: VecDeque::new(),
            waker: None,
            sender_count: 1,
            receiver_there: true,
        }));

        let sender = Sender {
            inner: inner.clone(),
        };
        let receiver = Receiver { inner };

        (sender, receiver)
    }
}

pub(super) fn yield_now() -> impl Future<Output = ()> {
    struct X(bool);

    impl Future for X {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<Self::Output> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    X(false)
}

pub(super) struct TimeoutFuture<F, T>
where
    F: Future<Output = T>,
{
    future: F,
    timeout_at: std::time::Instant,
}

pub(super) fn timeout_future<F, T>(future: F, timeout: std::time::Duration) -> TimeoutFuture<F, T>
where
    F: Future<Output = T> + Unpin,
{
    TimeoutFuture {
        future,
        timeout_at: std::time::Instant::now() + timeout,
    }
}

impl<F, T> Future for TimeoutFuture<F, T>
where
    F: Future<Output = T> + Unpin,
{
    type Output = DSSResult<T>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> std::task::Poll<Self::Output> {
        let now = std::time::Instant::now();

        if now >= self.timeout_at {
            trace!("A future timed out");
            return std::task::Poll::Ready(Err("Timeout".into()));
        }

        let timeout_at = self.timeout_at;

        let this = self.get_mut();
        let future = Pin::new(&mut this.future);
        let poll_res = future.poll(cx);

        match poll_res {
            Poll::Ready(output) => Poll::Ready(Ok(output)),
            Poll::Pending => {
                crate::trace!("Registering a timeout waker");
                let waker = cx.waker().clone();
                SLEEP_REGISTER.send((timeout_at, Box::new(waker))).unwrap();
                Poll::Pending
            }
        }
    }
}

pub(super) fn select2_noresult<F1: Future, F2: Future>(f1: F1, f2: F2) -> impl Future<Output = ()> {
    struct Select2Future<F1, F2> {
        f1: F1,
        f2: F2,
    }

    impl<F1: Future + Unpin, F2: Future + Unpin> Future for Select2Future<F1, F2> {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context,
        ) -> std::task::Poll<Self::Output> {
            let this = self.get_mut();

            let f1 = Pin::new(&mut this.f1);
            let f2 = Pin::new(&mut this.f2);

            let poll1 = f1.poll(cx);
            let poll2 = f2.poll(cx);

            if poll1.is_ready() || poll2.is_ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    Select2Future {
        f1: Box::pin(f1),
        f2: Box::pin(f2),
    }
}

// Join

struct Join2Futures<F1, F2, T1, T2>
where
    F1: Future<Output = T1>,
    F2: Future<Output = T2>,
{
    future1: F1,
    future2: F2,
    future1_result: Option<T1>,
    future2_result: Option<T2>,
}

impl<F1, F2, T1, T2> Future for Join2Futures<F1, F2, T1, T2>
where
    F1: Future<Output = T1> + Unpin,
    F2: Future<Output = T2> + Unpin,
    T1: Unpin,
    T2: Unpin,
{
    type Output = (T1, T2);

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> std::task::Poll<(T1, T2)> {
        let this = self.get_mut();

        if this.future1_result.is_none() {
            match Pin::new(&mut this.future1).poll(cx) {
                std::task::Poll::Ready(val) => this.future1_result = Some(val),
                std::task::Poll::Pending => {}
            }
        }

        if this.future2_result.is_none() {
            match Pin::new(&mut this.future2).poll(cx) {
                std::task::Poll::Ready(val) => this.future2_result = Some(val),
                std::task::Poll::Pending => {}
            }
        }

        if this.future1_result.is_none() || this.future2_result.is_none() {
            return std::task::Poll::Pending;
        }

        std::task::Poll::Ready((
            this.future1_result.take().unwrap(),
            this.future2_result.take().unwrap(),
        ))
    }
}

pub(super) fn join2<F1, F2, T1, T2>(future1: F1, future2: F2) -> impl Future<Output = (T1, T2)>
where
    F1: Future<Output = T1>,
    F2: Future<Output = T2>,
    T1: Unpin,
    T2: Unpin,
{
    Join2Futures {
        future1: Box::pin(future1),
        future2: Box::pin(future2),
        future1_result: None,
        future2_result: None,
    }
}

mod epoll {
    use std::{
        collections::HashMap,
        os::fd::{AsRawFd, BorrowedFd},
        sync::{Arc, Mutex},
        task::Waker,
    };

    use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

    use super::ArcFd;

    #[derive(PartialEq, Eq, Hash, Debug)]
    pub enum PollType {
        Read,
        Write,
    }

    struct ArcFdAndWaker(ArcFd, Waker);
    type WakerHashMap = HashMap<i32, ArcFdAndWaker>;

    pub fn epoll_task() -> super::mpsc::Sender<(ArcFd, PollType, Waker)> {
        let (sender, receiver) = super::mpsc::channel();
        let epoll = Arc::new(Epoll::new(EpollCreateFlags::empty()).unwrap());
        let waker_hashmap: Arc<Mutex<WakerHashMap>> = Arc::new(Mutex::new(HashMap::new()));

        // Registerer
        super::spawn(epoll_register_task(
            epoll.clone(),
            waker_hashmap.clone(),
            receiver,
        ));

        // Waker
        std::thread::spawn(move || epoll_waker_task(epoll.clone(), waker_hashmap.clone()));

        sender
    }

    fn epoll_waker_task(epoll: Arc<Epoll>, waker_hashmap: Arc<Mutex<WakerHashMap>>) {
        loop {
            let mut events = [EpollEvent::empty(); 128];
            let epoll = epoll.clone();

            let n = epoll.wait(&mut events, EpollTimeout::NONE).unwrap();

            let mut waker_hashmap = waker_hashmap.lock().unwrap();

            for event in events.iter().take(n) {
                let fd = event.data() as i32;

                if let Some(ArcFdAndWaker(_fd, waker)) = waker_hashmap.remove(&fd) {
                    waker.wake();
                }
            }
        }
    }

    async fn epoll_register_task(
        epoll: Arc<Epoll>,
        waker_hashmap: Arc<Mutex<WakerHashMap>>,
        receiver: super::mpsc::Receiver<(ArcFd, PollType, Waker)>,
    ) {
        while let Some((fd, polltype, waker)) = receiver.recv().await {
            let flags = match polltype {
                PollType::Read => EpollFlags::EPOLLIN | EpollFlags::EPOLLONESHOT,
                PollType::Write => EpollFlags::EPOLLOUT | EpollFlags::EPOLLONESHOT,
            };

            let raw_fd = fd.as_raw_fd();
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let _ = waker_hashmap
                .lock()
                .unwrap()
                .insert(raw_fd, ArcFdAndWaker(fd, waker));

            let mut ev = EpollEvent::new(flags, raw_fd as u64);

            match epoll.modify(borrowed_fd, &mut ev) {
                Ok(_) => {}
                // If the file descriptor is not found in the epoll instance, add it instead of modifying.
                Err(nix::errno::Errno::ENOENT) => epoll.add(borrowed_fd, ev).unwrap(),
                Err(e) => {
                    panic!("epoll modify failed: {:?}", e);
                }
            }
        }
    }
}

mod sleep {
    use std::{collections::BinaryHeap, task::Waker, time::Instant};

    struct InstantAndWaker(Instant, Box<Waker>);

    impl PartialEq for InstantAndWaker {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq for InstantAndWaker {}

    impl PartialOrd for InstantAndWaker {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(other.0.cmp(&self.0))
        }
    }

    impl Ord for InstantAndWaker {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            other.0.cmp(&self.0)
        }
    }

    pub(super) fn sleep_task(recv: std::sync::mpsc::Receiver<(Instant, Box<Waker>)>) {
        let mut sleep_queue: BinaryHeap<InstantAndWaker> = BinaryHeap::new();

        loop {
            while let Ok((instant, waker)) = recv.try_recv() {
                sleep_queue.push(InstantAndWaker(instant, waker));
            }

            let now = Instant::now();
            while let Some(InstantAndWaker(instant, _)) = sleep_queue.peek() {
                if instant <= &now {
                    if let Some(InstantAndWaker(_, waker)) = sleep_queue.pop() {
                        waker.wake_by_ref();
                    }
                } else {
                    break;
                }
            }

            if let Some(InstantAndWaker(instant, _)) = sleep_queue.peek() {
                let timeout = *instant - now;
                match recv.recv_timeout(timeout) {
                    Ok((instant, waker)) => {
                        sleep_queue.push(InstantAndWaker(instant, waker));
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }

            if let Ok((instant, waker)) = recv.recv() {
                sleep_queue.push(InstantAndWaker(instant, waker));
            }
        }
    }
}

/// Creates a future that will panic if polled after it has completed.
///
/// Rust futures are supposed to be polled until completion, and not polled after they return `Poll::Ready`. When people
/// write futures, they assume that this contract is upheld. But bugs happen, so we can wrap a future in this function
/// to catch futures that are polled after completion, and panic.
pub(super) fn fused<T>(future: impl Future<Output = T> + Unpin) -> impl Future<Output = T> {
    struct Fused<F, T>
    where
        F: Future<Output = T>,
    {
        future: F,
        resolved: bool,
    }

    impl<F: Future<Output = T> + Unpin, T> Future for Fused<F, T> {
        type Output = T;

        fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<Self::Output> {
            let this = self.get_mut();

            if this.resolved {
                panic!("Future polled after completion");
            }

            match Pin::new(&mut this.future).poll(cx) {
                Poll::Ready(v) => {
                    this.resolved = true;
                    Poll::Ready(v)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    Fused {
        future,
        resolved: false,
    }
}
