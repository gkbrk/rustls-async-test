use std::sync::{Arc, RwLock};

pub struct Cowboy<T> {
    inner: Arc<RwLock<T>>,
}

impl<T> Cowboy<T> {
    pub fn new(inner: T) -> Self {
        Cowboy { inner: Arc::new(RwLock::new(inner)) }
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<T> {
        self.inner.read().unwrap()
    }

    pub fn write(&self) -> std::sync::RwLockWriteGuard<T> {
        self.inner.write().unwrap()
    }

    pub fn r(&self) -> std::sync::RwLockReadGuard<T> {
        self.read()
    }

    pub fn w(&self) -> std::sync::RwLockWriteGuard<T> {
        self.write()
    }

    pub fn modify<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        let mut guard = self.write();
        f(&mut *guard);
    }

    pub fn set(&self, value: T) {
        let mut guard = self.write();
        *guard = value;
    }

    pub fn replace(&self, value: T) -> T {
        let mut guard = self.write();
        std::mem::replace(&mut *guard, value)
    }
}

impl<T> Clone for Cowboy<T> {
    fn clone(&self) -> Self {
        Cowboy {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Clone> Cowboy<T> {
    pub fn get_cloned(&self) -> T {
        self.read().clone()
    }
}

pub trait IntoCowboy: Sized {
    fn cowboy(self) -> Cowboy<Self>;
}

impl<T> IntoCowboy for T {
    fn cowboy(self) -> Cowboy<T> {
        Cowboy::new(self)
    }
}