//! The second stage of a connection's send path
//!
//! The connection driver builds a transmit with the connection locked and
//! leaves its 1-RTT packets in the clear. The task here protects them and
//! sends the transmit, so that neither the encryption nor the send syscall
//! runs inside the lock, or on the thread that builds the next transmit.

use std::{
    collections::VecDeque,
    future::Future,
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use proto::crypto::DeferredSeal;

use crate::{runtime::UdpSender, udp_transmit};

/// How many transmits may wait for the sending task, beside the one it holds
///
/// The driver stops building when the queue is full, which is how a socket
/// that would block holds the connection back. A transmit is timestamped as
/// sent when it is built, so the queue is kept short.
///
/// Closing the connection does not cancel what waits here: the transmits
/// built before the close are still sent, ahead of the packet that closes the
/// connection or, when it is the peer that closed, into the draining period.
/// That is this many and one, where a driver that sends for itself has the
/// one a blocked socket left it with.
const QUEUE_DEPTH: usize = 2;

/// How many transmits the sending task handles before it yields
const SEND_BUDGET: usize = 8;

/// A transmit on its way to the socket
#[derive(Debug)]
pub(crate) struct SendJob {
    pub(crate) transmit: proto::Transmit,
    pub(crate) buffer: Vec<u8>,
    /// The protection `buffer`'s packets still need
    pub(crate) seals: Vec<DeferredSeal>,
}

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<SendJob>,
    /// The sender of a rebound socket, until the sending task takes it. It
    /// replaces the task's sender ahead of everything unsent, the transmit
    /// the old socket holds back included: that socket may never take it.
    rebind: Option<Pin<Box<dyn UdpSender>>>,
    /// Buffers of sent transmits, for the driver to build into
    spare: Vec<(Vec<u8>, Vec<DeferredSeal>)>,
    /// The driver, to wake when a full queue has room again and on a send error
    driver: Option<Waker>,
    /// Whether the driver found the queue full
    driver_blocked: bool,
    /// The sending task, when it found the queue empty
    task: Option<Waker>,
    /// The sending task, while the socket holds its transmit back
    blocked: Option<Waker>,
    /// The first send error, until the driver takes it
    error: Option<io::Error>,
    /// Set when the driver is gone: the task drops what is unsent and ends
    closed: bool,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    /// How many datagrams the sender takes in one transmit. The driver cannot
    /// ask a sender it does not hold, and the answer changes: a socket stops
    /// taking batches when the kernel refuses one. The sending task writes it
    /// after each send, and with `state` locked, as a rebind does: a send
    /// under way on the socket that was replaced must not have the last word.
    max_segments: AtomicUsize,
    /// Whether the pipe is shut. The sending task holds this across each
    /// socket send, so shutting the pipe waits out a send that has started
    /// and none starts after it: a transmit the task has already taken off
    /// the queue is still cancelled.
    shut: Mutex<bool>,
}

/// The driver's end of the queue
#[derive(Debug)]
pub(crate) struct SendPipe(Arc<Shared>);

impl SendPipe {
    /// Creates the queue and the task that drains it into `sender`
    pub(crate) fn new(sender: Pin<Box<dyn UdpSender>>) -> (Self, SendTask) {
        let shared = Arc::new(Shared {
            state: Mutex::default(),
            max_segments: AtomicUsize::new(sender.max_transmit_segments().get()),
            shut: Mutex::default(),
        });
        let task = SendTask {
            shared: shared.clone(),
            sender,
            current: None,
        };
        (Self(shared), task)
    }

    /// Whether another transmit may be queued, with a buffer to build it in
    ///
    /// When the queue is full the driver is woken as soon as it no longer is.
    ///
    /// The driver calls this every time it is polled, and each call has a
    /// sending task that waits for the socket try it again. A sender need not
    /// wake every task that waits on its socket: the one iroh hands out wakes
    /// the last to ask, so a connection that shares the socket with another
    /// can be passed over when it becomes writable. Whatever polls the driver
    /// (a timer, a packet from the peer, the application) then restarts the
    /// send, as it did when the driver sent for itself.
    pub(crate) fn poll_ready(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Vec<u8>, Vec<DeferredSeal>)>> {
        let mut state = self.0.state.lock().unwrap();
        if let Some(e) = state.error.take() {
            return Poll::Ready(Err(e));
        }
        if !state
            .driver
            .as_ref()
            .is_some_and(|driver| driver.will_wake(cx.waker()))
        {
            state.driver = Some(cx.waker().clone());
        }
        let blocked = state.blocked.clone();
        let ready = match state.queue.len() >= QUEUE_DEPTH {
            true => {
                state.driver_blocked = true;
                Poll::Pending
            }
            false => Poll::Ready(Ok(state.spare.pop().unwrap_or_default())),
        };
        drop(state);
        if let Some(task) = blocked {
            task.wake();
        }
        ready
    }

    /// Returns a buffer that was taken with [`Self::poll_ready`] and not used
    pub(crate) fn give_back(&self, buffer: Vec<u8>, seals: Vec<DeferredSeal>) {
        self.0.state.lock().unwrap().spare.push((buffer, seals));
    }

    pub(crate) fn send(&self, job: SendJob) {
        let mut state = self.0.state.lock().unwrap();
        state.queue.push_back(job);
        let task = state.task.take();
        drop(state);
        if let Some(task) = task {
            task.wake();
        }
    }

    /// Has the sending task send through `sender` from now on
    pub(crate) fn rebind(&self, sender: Pin<Box<dyn UdpSender>>) {
        let mut state = self.0.state.lock().unwrap();
        self.0
            .max_segments
            .store(sender.max_transmit_segments().get(), Ordering::Relaxed);
        state.rebind = Some(sender);
        // An error the driver has not taken yet is the replaced socket's.
        state.error = None;
        let wakers = [state.task.take(), state.blocked.clone()];
        drop(state);
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    /// How many datagrams the sender takes in one transmit
    pub(crate) fn max_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.0.max_segments.load(Ordering::Relaxed)).expect("stored from one")
    }
}

/// The pipe goes with the connection's driver: the connection is drained by
/// then, or failed. A drained connection must send nothing more (RFC 9000,
/// section 10.2), so what is still queued is dropped with it.
impl Drop for SendPipe {
    fn drop(&mut self) {
        *self.0.shut.lock().unwrap() = true;
        let mut state = self.0.state.lock().unwrap();
        state.closed = true;
        let wakers = [state.task.take(), state.blocked.take()];
        drop(state);
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }
}

/// Protects and sends the transmits the driver queued, in order
#[derive(Debug)]
pub(crate) struct SendTask {
    shared: Arc<Shared>,
    sender: Pin<Box<dyn UdpSender>>,
    /// A transmit that is protected and waits for the socket
    current: Option<SendJob>,
}

impl SendTask {
    fn publish_max_segments(&self) {
        self.shared
            .max_segments
            .store(self.sender.max_transmit_segments().get(), Ordering::Relaxed);
    }
}

impl Future for SendTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        for _ in 0..SEND_BUDGET {
            let mut state = this.shared.state.lock().unwrap();
            if state.closed {
                // The driver is done, so the connection is drained or dead:
                // nothing more may be sent for it, whatever is still queued.
                return Poll::Ready(());
            }
            if let Some(sender) = state.rebind.take() {
                this.sender = sender;
                this.publish_max_segments();
            }
            if this.current.is_none() {
                match state.queue.pop_front() {
                    Some(mut job) => {
                        let driver = match std::mem::take(&mut state.driver_blocked) {
                            true => state.driver.clone(),
                            false => None,
                        };
                        drop(state);
                        if let Some(driver) = driver {
                            driver.wake();
                        }
                        for seal in job.seals.drain(..) {
                            seal.seal(&mut job.buffer);
                        }
                        this.current = Some(job);
                    }
                    None => {
                        state.task = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                }
            } else {
                drop(state);
            }
            let job = this.current.as_ref().expect("set above");
            let shut = this.shared.shut.lock().unwrap();
            if *shut {
                return Poll::Ready(());
            }
            let result = this.sender.as_mut().poll_send(
                &udp_transmit(&job.transmit, &job.buffer[..job.transmit.size]),
                cx,
            );
            drop(shut);
            let result = match result {
                Poll::Pending => {
                    // The sender wakes this task when the socket is writable,
                    // or it may not: the driver does too, see `poll_ready`.
                    let mut state = this.shared.state.lock().unwrap();
                    if state.closed {
                        // Closed since the check above, and after this
                        // nothing would wake the task but the socket.
                        return Poll::Ready(());
                    }
                    if state.rebind.is_some() {
                        // Rebound since the check above: the new socket may
                        // take what this one will not.
                        continue;
                    }
                    if !state
                        .blocked
                        .as_ref()
                        .is_some_and(|task| task.will_wake(cx.waker()))
                    {
                        state.blocked = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
                Poll::Ready(result) => result,
            };
            let job = this.current.take().expect("set above");
            let mut state = this.shared.state.lock().unwrap();
            state.blocked = None;
            state.spare.push((job.buffer, job.seals));
            if state.rebind.is_some() {
                // Rebound during the send: this sender no longer speaks for
                // the connection, with its limit or with its error.
                continue;
            }
            this.publish_max_segments();
            if let Err(e) = result {
                state.error.get_or_insert(e);
                let driver = state.driver.clone();
                drop(state);
                if let Some(driver) = driver {
                    driver.wake();
                }
            }
        }
        // More may be queued: let other tasks run first.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::atomic::AtomicBool,
        task::Wake,
    };

    use super::*;

    /// A sender that never wakes whoever it told to wait, as a socket shared
    /// with another connection does when that one asked later.
    #[derive(Debug, Default)]
    struct ForgetfulSender {
        writable: Arc<AtomicBool>,
        sent: Arc<AtomicUsize>,
        /// Datagrams per transmit, when more than one
        segments: Arc<AtomicUsize>,
    }

    impl UdpSender for ForgetfulSender {
        fn poll_send(
            self: Pin<&mut Self>,
            _transmit: &udp::Transmit<'_>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            match self.writable.load(Ordering::Relaxed) {
                true => {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                    Poll::Ready(Ok(()))
                }
                false => Poll::Pending,
            }
        }

        fn max_transmit_segments(&self) -> NonZeroUsize {
            NonZeroUsize::new(self.segments.load(Ordering::Relaxed)).unwrap_or(NonZeroUsize::MIN)
        }
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn job(buffer: Vec<u8>, seals: Vec<DeferredSeal>) -> SendJob {
        SendJob {
            transmit: proto::Transmit {
                destination: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                ecn: None,
                size: 16,
                segment_size: None,
                src_ip: None,
            },
            buffer: [buffer, vec![0; 16]].concat(),
            seals,
        }
    }

    /// A sending task that waits for the socket ends with its connection,
    /// without the socket's help and without sending what is queued.
    #[test]
    fn blocked_send_ends_with_the_connection() {
        let sender = ForgetfulSender::default();
        let (writable, sent) = (sender.writable.clone(), sender.sent.clone());
        let (pipe, mut task) = SendPipe::new(Box::pin(sender));
        let (driver_wakes, task_wakes) = (Arc::new(Wakes::default()), Arc::new(Wakes::default()));
        let (driver_waker, task_waker) = (driver_wakes.into(), task_wakes.clone().into());
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        for _ in 0..2 {
            let Poll::Ready(Ok((buffer, seals))) = pipe.poll_ready(driver) else {
                panic!("room in the queue");
            };
            pipe.send(job(buffer, seals));
        }
        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        let woken = task_wakes.0.load(Ordering::Relaxed);

        drop(pipe);
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken + 1);
        // The socket would take the queued transmits now: they are not sent.
        writable.store(true, Ordering::Relaxed);
        assert!(Pin::new(&mut task).poll(task_cx).is_ready());
        assert_eq!(sent.load(Ordering::Relaxed), 0);
    }

    /// A driver waker that shuts the pipe: the task wakes the driver between
    /// taking a transmit off the queue and sending it.
    struct ShutOnWake(Mutex<Option<SendPipe>>);

    impl Wake for ShutOnWake {
        fn wake(self: Arc<Self>) {
            self.0.lock().unwrap().take();
        }
    }

    /// A transmit the task has taken off the queue is not sent once the pipe
    /// is shut, even with the socket ready for it.
    #[test]
    fn shutdown_cancels_a_dequeued_send() {
        let sender = ForgetfulSender::default();
        let (writable, sent) = (sender.writable.clone(), sender.sent.clone());
        writable.store(true, Ordering::Relaxed);
        let (pipe, mut task) = SendPipe::new(Box::pin(sender));
        let driver_wakes = Arc::new(ShutOnWake(Mutex::new(Some(pipe))));
        let (driver_waker, task_waker) = (
            driver_wakes.clone().into(),
            Arc::new(Wakes::default()).into(),
        );
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        // A full queue, and a driver that waits for room in it.
        {
            let pipe = driver_wakes.0.lock().unwrap();
            let pipe = pipe.as_ref().unwrap();
            for _ in 0..QUEUE_DEPTH {
                let Poll::Ready(Ok((buffer, seals))) = pipe.poll_ready(driver) else {
                    panic!("room in the queue");
                };
                pipe.send(job(buffer, seals));
            }
            assert!(pipe.poll_ready(driver).is_pending());
        }

        assert!(Pin::new(&mut task).poll(task_cx).is_ready());
        assert!(driver_wakes.0.lock().unwrap().is_none());
        assert_eq!(sent.load(Ordering::Relaxed), 0);
    }

    /// A sending task the socket never wakes sends again once the driver is
    /// polled, with the queue full or not.
    #[test]
    fn driver_restarts_a_send_the_socket_did_not_wake() {
        let sender = ForgetfulSender::default();
        let (writable, sent) = (sender.writable.clone(), sender.sent.clone());
        let (pipe, mut task) = SendPipe::new(Box::pin(sender));
        let (driver_wakes, task_wakes) = (Arc::new(Wakes::default()), Arc::new(Wakes::default()));
        let (driver_waker, task_waker) = (driver_wakes.clone().into(), task_wakes.clone().into());
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        // One transmit with the task, and the queue full behind it.
        for _ in 0..QUEUE_DEPTH + 1 {
            let Poll::Ready(Ok((buffer, seals))) = pipe.poll_ready(driver) else {
                panic!("room in the queue");
            };
            pipe.send(job(buffer, seals));
            assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        }
        assert!(pipe.poll_ready(driver).is_pending());
        assert_eq!(sent.load(Ordering::Relaxed), 0);

        // The socket turns writable and tells nobody.
        writable.store(true, Ordering::Relaxed);
        let woken = task_wakes.0.load(Ordering::Relaxed);
        assert!(pipe.poll_ready(driver).is_pending());
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken + 1);

        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        assert_eq!(sent.load(Ordering::Relaxed), QUEUE_DEPTH + 1);
        // Making room woke the driver, and nothing waits for the socket now.
        assert!(driver_wakes.0.load(Ordering::Relaxed) > 0);
        let woken = task_wakes.0.load(Ordering::Relaxed);
        assert!(pipe.poll_ready(driver).is_ready());
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken);

        // The same with room in the queue.
        writable.store(false, Ordering::Relaxed);
        pipe.send(job(Vec::new(), Vec::new()));
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken + 1);
        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        writable.store(true, Ordering::Relaxed);
        assert!(pipe.poll_ready(driver).is_ready());
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken + 2);
        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        assert_eq!(sent.load(Ordering::Relaxed), QUEUE_DEPTH + 2);
    }

    /// A rebound socket's sender takes over at once, the transmit the old
    /// socket holds back included: that socket may never be writable again.
    #[test]
    fn rebind_takes_over_a_blocked_send() {
        let old = ForgetfulSender::default();
        let old_sent = old.sent.clone();
        let (pipe, mut task) = SendPipe::new(Box::pin(old));
        let (driver_wakes, task_wakes) = (Arc::new(Wakes::default()), Arc::new(Wakes::default()));
        let (driver_waker, task_waker) = (driver_wakes.into(), task_wakes.clone().into());
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        // One transmit with the task, and the queue full behind it.
        for _ in 0..QUEUE_DEPTH + 1 {
            let Poll::Ready(Ok((buffer, seals))) = pipe.poll_ready(driver) else {
                panic!("room in the queue");
            };
            pipe.send(job(buffer, seals));
            assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        }

        let new = ForgetfulSender::default();
        new.writable.store(true, Ordering::Relaxed);
        let new_sent = new.sent.clone();
        let woken = task_wakes.0.load(Ordering::Relaxed);
        pipe.rebind(Box::pin(new));
        assert_eq!(task_wakes.0.load(Ordering::Relaxed), woken + 1);

        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        assert_eq!(new_sent.load(Ordering::Relaxed), QUEUE_DEPTH + 1);
        assert_eq!(old_sent.load(Ordering::Relaxed), 0);
    }

    /// The driver learns of a sender that stops taking batches, as a socket
    /// does when the kernel refuses one, and of a rebound socket's limit.
    #[test]
    fn segment_limit_follows_the_sender() {
        let sender = ForgetfulSender::default();
        let segments = sender.segments.clone();
        segments.store(32, Ordering::Relaxed);
        sender.writable.store(true, Ordering::Relaxed);
        let (pipe, mut task) = SendPipe::new(Box::pin(sender));
        let waker = Arc::new(Wakes::default()).into();
        let cx = &mut Context::from_waker(&waker);
        assert_eq!(pipe.max_segments().get(), 32);

        segments.store(1, Ordering::Relaxed);
        pipe.send(job(Vec::new(), Vec::new()));
        assert!(Pin::new(&mut task).poll(cx).is_pending());
        assert_eq!(pipe.max_segments().get(), 1);

        let rebound = ForgetfulSender::default();
        rebound.segments.store(16, Ordering::Relaxed);
        pipe.rebind(Box::pin(rebound));
        assert_eq!(pipe.max_segments().get(), 16);
        assert!(Pin::new(&mut task).poll(cx).is_pending());
        assert_eq!(pipe.max_segments().get(), 16);
    }

    /// A sender whose socket is rebound while it sends, and fails the send.
    struct ReboundSender(Mutex<Option<Box<dyn FnOnce() + Send>>>);

    impl std::fmt::Debug for ReboundSender {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ReboundSender")
        }
    }

    impl UdpSender for ReboundSender {
        fn poll_send(
            self: Pin<&mut Self>,
            _transmit: &udp::Transmit<'_>,
            _cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(rebind) = self.0.lock().unwrap().take() {
                rebind();
            }
            Poll::Ready(Err(io::Error::other("the socket is gone")))
        }

        fn max_transmit_segments(&self) -> NonZeroUsize {
            NonZeroUsize::new(32).unwrap()
        }
    }

    /// A send that was under way when the socket was rebound speaks for the
    /// old socket only: its error does not end the connection, and its limit
    /// does not replace the new socket's.
    #[test]
    fn rebind_supersedes_a_send_under_way() {
        let new = ForgetfulSender::default();
        new.writable.store(true, Ordering::Relaxed);
        new.segments.store(4, Ordering::Relaxed);
        let new_sent = new.sent.clone();
        let rebind = Arc::new(Mutex::new(None::<Box<dyn FnOnce() + Send>>));
        let (pipe, mut task) =
            SendPipe::new(Box::pin(ReboundSender(Mutex::new(Some(Box::new({
                let rebind = rebind.clone();
                move || (rebind.lock().unwrap().take().unwrap())()
            }))))));
        let pipe = Arc::new(pipe);
        *rebind.lock().unwrap() = Some(Box::new({
            let pipe = pipe.clone();
            move || pipe.rebind(Box::pin(new))
        }));
        let (driver_waker, task_waker) = (
            Arc::new(Wakes::default()).into(),
            Arc::new(Wakes::default()).into(),
        );
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        for _ in 0..2 {
            pipe.send(job(Vec::new(), Vec::new()));
        }
        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        assert_eq!(new_sent.load(Ordering::Relaxed), 1);
        assert_eq!(pipe.max_segments().get(), 4);
        assert!(matches!(pipe.poll_ready(driver), Poll::Ready(Ok(_))));
    }

    /// Nor does an error the old socket left for the driver before the
    /// rebind end the connection.
    #[test]
    fn rebind_clears_the_old_socket_error() {
        let (pipe, mut task) = SendPipe::new(Box::pin(ReboundSender(Mutex::new(None))));
        let (driver_waker, task_waker) = (
            Arc::new(Wakes::default()).into(),
            Arc::new(Wakes::default()).into(),
        );
        let driver = &mut Context::from_waker(&driver_waker);
        let task_cx = &mut Context::from_waker(&task_waker);

        pipe.send(job(Vec::new(), Vec::new()));
        assert!(Pin::new(&mut task).poll(task_cx).is_pending());
        pipe.rebind(Box::pin(ForgetfulSender::default()));
        assert!(matches!(pipe.poll_ready(driver), Poll::Ready(Ok(_))));
    }
}
