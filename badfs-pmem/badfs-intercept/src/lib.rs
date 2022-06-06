#![feature(once_cell)]
#![feature(test)]
extern crate test;

#[macro_use]
extern crate log;

use std::borrow::{Borrow, BorrowMut};
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};

use ctor::{ctor, dtor};
use once_cell::sync::OnceCell;
use std::lazy::SyncLazy;
use std::sync::{Mutex, RwLock};

use libc::c_long;

use badfs_client::BadfsClient;
use badfs_common::error::Error::ForwardToKernel;
use std::time::Duration;

static CLIENT: SyncLazy<RwLock<Option<BadfsClient>>> = SyncLazy::new(|| RwLock::new(None));
static LOGGER_INITED: OnceCell<()> = OnceCell::new();
static TASK_COUNT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // thread local tokio runtime, blocking when there is a async request
    static TOKIO_RUNTIME: SyncLazy<tokio::runtime::Runtime> = SyncLazy::new(||{
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    });
    // only intercept the initial thread, filter out threads spawned by ourselves
    static ENABLE_INTERCEPT: Cell<bool> = Cell::new(false);
    // forbid recursive interception
    static INTERCEPTED: Cell<bool> = Cell::new(false);
}

#[ctor]
fn init() {
    LOGGER_INITED.get_or_init(|| {
        env_logger::init();
        info!(
            "env_logger has initialized.(thread_id: {:?})",
            std::thread::current().id()
        );
    });

    //create a new client in a really thread-safe way
    let mut guard = CLIENT.write().unwrap();
    if let None = *guard {
        *guard = Some({
            TOKIO_RUNTIME.with(|tokio| {
                tokio.block_on(async {
                    let client = BadfsClient::new().await.expect("failed to create client");
                    info!(
                        "Badfs Client has initialized.(thread_id: {:?})",
                        std::thread::current().id()
                    );
                    client
                })
            })
        });
    }

    unsafe {
        intercept_hook_point = Some(intercept_hook);
        info!(
            "intercept_hook_point has been set to our hook.(thread_id: {:?})",
            std::thread::current().id()
        );
    }
    ENABLE_INTERCEPT.with(|f| {
        info!(
            "enabled intercept hook for current thread.(thread_id: {:?})",
            std::thread::current().id()
        );
        f.set(true);
    });
}

#[dtor]
fn destroy() {
    info!("entering dtor.");
    ENABLE_INTERCEPT.with(|enable| enable.set(false));
    // set intercept_hook_point to nullptr so that it will not access to the dropped variables
    unsafe {
        intercept_hook_point = None;
        info!("intercept_hook_point uninstalled.");
    }
    let mut guard = CLIENT.write().unwrap();
    *guard = None;
}

#[repr(usize)]
enum InterceptResult {
    Hook = 0,
    Forward = 1,
}

#[link(name = "syscall_intercept")]
extern "C" {
    static mut intercept_hook_point: Option<
        extern "C" fn(
            num: c_long,
            a0: c_long,
            a1: c_long,
            a2: c_long,
            a3: c_long,
            a4: c_long,
            a5: c_long,
            result: &mut c_long,
        ) -> InterceptResult,
    >;
}

extern "C" fn intercept_hook(
    num: c_long,
    a0: c_long,
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
    result: &mut c_long,
) -> InterceptResult {
    if !ENABLE_INTERCEPT.with(|f| f.get()) || INTERCEPTED.with(|f| f.get()) {
        return InterceptResult::Forward;
    }
    INTERCEPTED.with(|f| f.set(true));
    TASK_COUNT.fetch_add(1, Ordering::SeqCst);
    // trace!("{},{},{},{},{},{},{}", num, a0, a1, a2, a3, a4, a5);
    let syscall_result = TOKIO_RUNTIME.try_with(|tokio| {
        tokio.block_on(async {
            CLIENT
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .syscall(num, a0, a1, a2, a3, a4, a5)
                .await
        })
    });
    let syscall_result = {
        match syscall_result {
            Ok(result) => result,
            Err(_) => return InterceptResult::Forward,
        }
    };
    TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    let intercept_result = match syscall_result {
        Ok(syscall_result) => {
            *result = syscall_result;
            InterceptResult::Hook
        }
        Err(badfs_common::error::Error::ForwardToKernel) => InterceptResult::Forward,
        Err(unexpected_error) => {
            panic!("unexpected error:{:?}", unexpected_error)
        }
    };
    INTERCEPTED.with(|f| f.set(false));
    intercept_result
}

#[cfg(test)]
mod tests {
    use std::lazy::SyncLazy;
    use std::sync::RwLock;
    use test::Bencher;

    fn fetch_from_option<T, U>(o: &Option<T>, accessor: impl Fn(&T) -> U) -> U {
        accessor(o.as_ref().unwrap())
    }

    fn fetch_from_rwlock_option<T, U>(o: &RwLock<Option<T>>, accessor: impl Fn(&T) -> U) -> U {
        let guard = o.read().unwrap();
        accessor(guard.as_ref().unwrap())
    }

    #[bench]
    fn test_pure_option(b: &mut Bencher) {
        let o = Some(2);
        b.iter(|| fetch_from_option(&o, |i| i + 1))
    }

    #[bench]
    fn test_rwlock_option(b: &mut Bencher) {
        let o = RwLock::new(Some(2));
        b.iter(|| fetch_from_rwlock_option(&o, |i| i + 1))
    }

    #[bench]
    fn test_lazy_init_rwlock_option(b: &mut Bencher) {
        let o = SyncLazy::new(|| RwLock::new(Some(2)));
        b.iter(|| fetch_from_rwlock_option(&o, |i| i + 1))
    }
}
