//! Tests for receive windows that grow with their stream's reader
//! ([`TransportConfig::max_stream_receive_window`](crate::TransportConfig::max_stream_receive_window))

use core::time::Duration;

use crate::{Dir, Side::*, StreamId, VarInt, WriteError};

use super::util::{ConnPair, subscribe};

/// The window every stream starts with
const BASE: u64 = 16 * 1024;
/// The window a stream may grow to: three doublings
const MAX: u64 = 128 * 1024;
/// One way, so a round trip is twice this
const LATENCY: Duration = Duration::from_millis(10);

/// A connection whose server lets its streams' receive windows grow by `budget` between them
fn connect(budget: u64) -> ConnPair {
    let mut builder = ConnPair::builder().with_latency(LATENCY);
    builder
        .server_transport_cfg
        .stream_receive_window(VarInt::from_u64(BASE).unwrap())
        .max_stream_receive_window(VarInt::from_u64(MAX).unwrap())
        .stream_receive_window_budget(budget);
    builder.connect()
}

/// A stream the client writes and the server reads
struct Transfer {
    id: StreamId,
    written: u64,
    read: u64,
}

impl Transfer {
    fn open(pair: &mut ConnPair) -> Self {
        let id = pair.streams(Client).open(Dir::Uni).unwrap();
        Self {
            id,
            written: 0,
            read: 0,
        }
    }

    /// Write as much as flow control takes
    fn write(&mut self, pair: &mut ConnPair) {
        let data = [0xAB; 16 * 1024];
        loop {
            match pair.send_stream(Client, self.id).write(&data) {
                Ok(n) => self.written += n as u64,
                Err(WriteError::Blocked) => break,
                Err(e) => panic!("write: {e}"),
            }
        }
    }

    /// Read everything that has arrived
    fn read(&mut self, pair: &mut ConnPair) {
        let mut recv = pair.recv_stream(Server, self.id);
        let Ok(mut chunks) = recv.read(true) else {
            return;
        };
        while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
            self.read += chunk.bytes.len() as u64;
        }
        let _ = chunks.finalize();
    }

    /// Carry `bytes` with a reader that takes everything the moment it arrives
    fn run_read_at_once(&mut self, pair: &mut ConnPair, bytes: u64) {
        let until = self.read + bytes;
        while self.read < until {
            // Each side's application runs between its connection taking what has arrived and
            // sending what that leads to, so credit turns into data, and data into credit, at
            // the instant it arrives.
            pair.drive_client();
            self.write(pair);
            pair.drive_client();
            pair.drive_server();
            self.read(pair);
            pair.drive_server();
            pair.advance_time();
        }
    }

    /// Carry `windows` windows of data with a reader that takes one a second
    fn run_read_slowly(&mut self, pair: &mut ConnPair, windows: usize) {
        for _ in 0..windows {
            self.write(pair);
            pair.drive();
            pair.time += Duration::from_secs(1);
            self.read(pair);
        }
    }

    /// How far the writer gets ahead of a reader that has stopped: the credit the stream holds
    ///
    /// Updates go out for every eighth of a window that is read, so this is between seven
    /// eighths of the stream's window and all of it.
    fn credit(&mut self, pair: &mut ConnPair) -> u64 {
        loop {
            // Whatever is on its way arrives, the last window update included.
            pair.drive();
            let before = self.written;
            self.write(pair);
            if self.written == before {
                break;
            }
        }
        self.written - self.read
    }
}

#[track_caller]
fn assert_window(credit: u64, window: u64) {
    assert!(
        credit > window - window / 8 && credit <= window,
        "credit of {credit} is not that of a {window} window"
    );
}

#[test]
fn a_window_grows_while_its_reader_keeps_up() {
    let _guard = subscribe();
    let mut pair = connect(u64::MAX);
    let mut stream = Transfer::open(&mut pair);
    stream.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(stream.credit(&mut pair), MAX);
}

#[test]
fn a_window_stays_as_it_was_for_a_slow_reader() {
    let _guard = subscribe();
    let mut pair = connect(u64::MAX);
    let mut stream = Transfer::open(&mut pair);
    stream.run_read_slowly(&mut pair, 32);
    assert_window(stream.credit(&mut pair), BASE);

    // A reader that speeds up is given more, and keeps it when it slows down again.
    stream.run_read_at_once(&mut pair, 32 * MAX);
    stream.run_read_slowly(&mut pair, 8);
    assert_window(stream.credit(&mut pair), MAX);
}

#[test]
fn nothing_grows_unless_configured() {
    let _guard = subscribe();
    let mut builder = ConnPair::builder().with_latency(LATENCY);
    builder
        .server_transport_cfg
        .stream_receive_window(VarInt::from_u64(BASE).unwrap());
    let mut pair = builder.connect();
    let mut stream = Transfer::open(&mut pair);
    stream.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(stream.credit(&mut pair), BASE);
}

#[test]
fn windows_grow_out_of_one_budget() {
    let _guard = subscribe();
    // Enough for one stream to reach the maximum, and half as much again.
    let grown = MAX - BASE;
    let mut pair = connect(grown + grown / 2);

    let mut first = Transfer::open(&mut pair);
    first.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(first.credit(&mut pair), MAX);

    // The second doubles twice, and the third doubling gets what is left.
    let mut second = Transfer::open(&mut pair);
    second.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(second.credit(&mut pair), BASE + grown / 2);

    // The third finds nothing, and carries its data with the window it started with while
    // the other two sit on theirs unread.
    let mut third = Transfer::open(&mut pair);
    third.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(third.credit(&mut pair), BASE);

    // What a stream took is back once it is stopped...
    pair.recv_stream(Server, first.id)
        .stop(VarInt::from_u32(0))
        .unwrap();
    third.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(third.credit(&mut pair), MAX);

    // ...or has been read to its end.
    pair.send_stream(Client, second.id).finish().unwrap();
    pair.drive();
    second.read(&mut pair);
    assert_eq!(second.read, second.written);
    let mut fourth = Transfer::open(&mut pair);
    fourth.run_read_at_once(&mut pair, 32 * MAX);
    assert_window(fourth.credit(&mut pair), BASE + grown / 2);
}
