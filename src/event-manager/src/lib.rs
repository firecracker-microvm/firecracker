#![warn(clippy::pedantic)]

use std::collections::HashMap;
use std::mem::transmute;
use std::os::unix::io::{AsRawFd, RawFd};

use utils::epoll::EventSet;

/// The function thats runs when an event occurs.
type Action = Box<dyn Fn(&mut EventManager, EventSet)>;

/// We store the event file descriptor under `libc::epoll_event.u64` this is safe.
// TODO Can this be done better?
fn i32_to_u64(x: RawFd) -> u64 {
    // SAFETY:
    // Always safe.
    unsafe { transmute([[0, 0, 0, 0], x.to_ne_bytes()]) }
}
/// We store the event file descriptor under `libc::epoll_event.u64` this is safe.
// TODO Can this be done better?
fn u64_to_i32(x: u64) -> RawFd {
    // SAFETY:
    // Always safe.
    RawFd::from_ne_bytes(unsafe { x.to_ne_bytes()[4..8].try_into().unwrap_unchecked() })
}

pub struct EventManager {
    epfd: RawFd,
    events: HashMap<RawFd, Action>,
}
impl EventManager {
    /// Add an entry to the interest list of the epoll file descriptor.
    ///
    /// # Errors
    ///
    /// When [`libc::epoll_ctl`] returns `-1`.
    pub fn add<T: AsRawFd>(&mut self, fd: T, events: EventSet, f: Action) -> Result<(), i32> {
        let mut event = libc::epoll_event {
            events: events.bits(),
            r#u64: i32_to_u64(fd.as_raw_fd()),
        };
        match unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd.as_raw_fd(), &mut event) }
        {
            0 => {
                self.events.insert(fd.as_raw_fd(), f);
                Ok(())
            }
            -1 => Err(errno()),
            _ => unreachable!(),
        }
    }
    /// Remove (deregister) the target file descriptor fd from the interest list.
    ///
    /// Returns `Ok(true)` when the given `fd` was present and `Ok(false)` when it wasn't.
    ///
    /// # Errors
    ///
    /// When [`libc::epoll_ctl`] returns `-1`.
    pub fn del<T: AsRawFd>(&mut self, fd: T) -> Result<bool, i32> {
        match self.events.remove(&fd.as_raw_fd()) {
            Some(_) => {
                match unsafe {
                    libc::epoll_ctl(
                        self.epfd,
                        libc::EPOLL_CTL_DEL,
                        fd.as_raw_fd(),
                        std::ptr::null_mut(),
                    )
                } {
                    0 => Ok(true),
                    -1 => Err(errno()),
                    _ => unreachable!(),
                }
            }
            None => Ok(false),
        }
    }
    /// Waits until an event fires then triggers the respective action returning `Ok(Some)`. If
    /// timeout is `Some(_)` it may also return after the given number of milliseconds with
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// When [`libc::epoll_wait`] returns `-1`.
    ///
    /// # Panics
    ///
    /// When the value given in timeout does not fit within an `i32` e.g.
    /// `timeout.map(|u| i32::try_from(u).unwrap())`.
    pub fn wait(&mut self, timeout: Option<u32>) -> Result<bool, i32> {
        // Since we use `maxevents=1` we only need to have 1 event in memory.
        let mut uninit_event = std::mem::MaybeUninit::<libc::epoll_event>::uninit();
        match unsafe {
            libc::epoll_wait(
                self.epfd,
                uninit_event.as_mut_ptr(),
                1,
                timeout.map_or(-1i32, |u| i32::try_from(u).unwrap()),
            )
        } {
            -1 => Err(errno()),
            0 => Ok(false),
            1 => {
                let event = unsafe { uninit_event.assume_init() };

                // TODO Clean this
                unsafe {
                    // For all events which can fire there exists an entry within `self.events` thus
                    // it is safe to unwrap here.
                    let f: *const dyn Fn(&mut EventManager, EventSet) =
                        self.events.get(&(u64_to_i32(event.u64))).unwrap();
                    (*f)(self, EventSet::from_bits_unchecked(event.events));
                }

                Ok(true)
            }
            _ => unreachable!(),
        }
    }
    /// Creates new event manager.
    ///
    /// # Errors
    ///
    /// When [`libc::epoll_create1`] returns `-1`.
    pub fn new(close_exec: bool) -> Result<Self, i32> {
        match unsafe { libc::epoll_create1(if close_exec { libc::EPOLL_CLOEXEC } else { 0 }) } {
            -1 => Err(errno()),
            epfd => Ok(Self {
                epfd,
                events: HashMap::new(),
            }),
        }
    }
}
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}
impl Default for EventManager {
    fn default() -> Self {
        Self::new(false).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static COUNT: AtomicBool = AtomicBool::new(false);
        let mut manager = EventManager::default();
        // We set value to 1 so it will trigger on a read event.
        let event_fd = unsafe {
            let fd = libc::eventfd(1, 0);
            assert_ne!(fd, -1);
            fd
        };
        manager
            .add(
                event_fd,
                EventSet::IN,
                Box::new(move |x: &mut EventManager, _: EventSet| {
                    let cur = COUNT.load(Ordering::SeqCst);
                    COUNT.store(!cur, Ordering::SeqCst);
                    x.del(event_fd).unwrap();
                }),
            )
            .unwrap();

        assert!(!COUNT.load(Ordering::SeqCst));
        assert_eq!(manager.wait(Some(10)), Ok(true));
        assert!(COUNT.load(Ordering::SeqCst));

        // Somce the evemt will have been deleted by the last event, it will timeout.
        assert_eq!(manager.wait(Some(10)), Ok(false));
        assert!(COUNT.load(Ordering::SeqCst));
        assert_eq!(manager.wait(Some(10)), Ok(false));
        assert!(COUNT.load(Ordering::SeqCst));
    }
    #[test]
    fn flip() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static COUNT: AtomicBool = AtomicBool::new(false);
        let mut manager = EventManager::default();
        // We set value to 1 so it will trigger on a read event.
        let event_fd = unsafe {
            let fd = libc::eventfd(1, 0);
            assert_ne!(fd, -1);
            fd
        };
        manager
            .add(
                event_fd,
                EventSet::IN,
                Box::new(|_: &mut EventManager, _: EventSet| {
                    let cur = COUNT.load(Ordering::SeqCst);
                    COUNT.store(!cur, Ordering::SeqCst);
                }),
            )
            .unwrap();

        assert!(!COUNT.load(Ordering::SeqCst));
        assert_eq!(manager.wait(Some(10)), Ok(true));
        assert!(COUNT.load(Ordering::SeqCst));
        assert_eq!(manager.wait(Some(10)), Ok(true));
        assert!(!COUNT.load(Ordering::SeqCst));
    }
}
