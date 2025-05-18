use super::{ArcFd, DSSResult, read_fd, write_fd};

pub(crate) trait AsyncRead {
    async fn read(&self, buf: &mut [u8]) -> DSSResult<usize>;
}

impl AsyncRead for ArcFd {
    async fn read(&self, buf: &mut [u8]) -> DSSResult<usize> {
        read_fd(self, buf).await
    }
}

pub(crate) trait AsyncWrite {
    async fn write(&self, buf: &[u8]) -> DSSResult<usize>;
}

impl AsyncWrite for ArcFd {
    async fn write(&self, buf: &[u8]) -> DSSResult<usize> {
        write_fd(self, buf).await
    }
}
