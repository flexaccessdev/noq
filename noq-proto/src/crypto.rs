//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic in noq is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{any::Any, str};

use bytes::BytesMut;

use crate::{
    ConnectError, PathId, Side, TransportError, shared::ConnectionId,
    transport_parameters::TransportParameters,
};

/// Cryptography interface based on ring or aws-lc-rs.
///
/// Prefers ring, if both are enabled.
#[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(feature = "rustls")]
pub mod rustls;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sync + 'static {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, dst_cid: ConnectionId, side: Side) -> Keys;

    /// Get data negotiated during the handshake, if available
    ///
    /// Returns `None` until the connection emits `HandshakeDataReady`.
    fn handshake_data(&self) -> Option<Box<dyn Any>>;

    /// Get the peer's identity, if available
    fn peer_identity(&self) -> Option<Box<dyn Any>>;

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
    ///
    /// On success, returns `true` iff `self.handshake_data()` has been populated.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>>;

    /// Verify the integrity of a retry packet
    ///
    /// See the specification: <https://www.rfc-editor.org/rfc/rfc9001#name-retry-packet-integrity>
    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool;

    /// Fill `output` with `output.len()` bytes of keying material derived
    /// from the [Session]'s secrets, using `label` and `context` for domain
    /// separation.
    ///
    /// This function will fail, returning [ExportKeyingMaterialError],
    /// if the requested output length is too large.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError>;
}

/// A pair of keys for bidirectional communication
pub struct KeyPair<T> {
    /// Key for encrypting data
    pub local: T,
    /// Key for decrypting data
    pub remote: T,
}

/// A complete set of keys for a certain packet space
pub struct Keys {
    /// Header protection keys
    pub header: KeyPair<Box<dyn HeaderKey>>,
    /// Packet protection keys
    pub packet: KeyPair<Box<dyn PacketKey>>,
}

impl Keys {
    pub(crate) fn local(&self) -> (&dyn HeaderKey, &dyn PacketKey) {
        (self.header.local.as_ref(), self.packet.local.as_ref())
    }

    pub(crate) fn remote(&self) -> (&dyn HeaderKey, &dyn PacketKey) {
        (self.header.remote.as_ref(), self.packet.remote.as_ref())
    }
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        &self,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, version: u32, dst_cid: ConnectionId)
    -> Result<Keys, UnsupportedVersion>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    ///
    /// See the specification: <https://www.rfc-editor.org/rfc/rfc9001#name-retry-packet-integrity>
    fn retry_tag(&self, version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16];

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(&self, version: u32, params: &TransportParameters) -> Box<dyn Session>;
}

/// Keys used to protect packet payloads
pub trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, path_id: PathId, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        path_id: PathId,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers
pub trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

impl PacketKey for Arc<dyn PacketKey> {
    fn encrypt(&self, path_id: PathId, packet: u64, buf: &mut [u8], header_len: usize) {
        (**self).encrypt(path_id, packet, buf, header_len)
    }

    fn decrypt(
        &self,
        path_id: PathId,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        (**self).decrypt(path_id, packet, header, payload)
    }

    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        (**self).confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        (**self).integrity_limit()
    }
}

impl HeaderKey for Arc<dyn HeaderKey> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        (**self).decrypt(pn_offset, packet)
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        (**self).encrypt(pn_offset, packet)
    }

    fn sample_size(&self) -> usize {
        (**self).sample_size()
    }
}

/// Stands in for a key for the moment it is moved into a shared handle
pub(crate) struct TakenKey;

impl PacketKey for TakenKey {
    fn encrypt(&self, _: PathId, _: u64, _: &mut [u8], _: usize) {
        unreachable!("placeholder key")
    }

    fn decrypt(&self, _: PathId, _: u64, _: &[u8], _: &mut BytesMut) -> Result<(), CryptoError> {
        unreachable!("placeholder key")
    }

    fn tag_len(&self) -> usize {
        unreachable!("placeholder key")
    }

    fn confidentiality_limit(&self) -> u64 {
        unreachable!("placeholder key")
    }

    fn integrity_limit(&self) -> u64 {
        unreachable!("placeholder key")
    }
}

impl HeaderKey for TakenKey {
    fn decrypt(&self, _: usize, _: &mut [u8]) {
        unreachable!("placeholder key")
    }

    fn encrypt(&self, _: usize, _: &mut [u8]) {
        unreachable!("placeholder key")
    }

    fn sample_size(&self) -> usize {
        unreachable!("placeholder key")
    }
}

/// A 1-RTT packet written to a transmit buffer in the clear, and what protects it
///
/// With [`Connection::set_deferred_seal`] a connection leaves the protection of its 1-RTT
/// packets to the caller, which applies it with [`Self::seal`] before sending the buffer.
/// That lets the cost of encryption leave the critical section the connection is driven in.
///
/// [`Connection::set_deferred_seal`]: crate::Connection::set_deferred_seal
pub struct DeferredSeal {
    /// Where the packet starts in the transmit buffer
    pub(crate) start: usize,
    /// Where the packet ends, authentication tag included
    pub(crate) end: usize,
    pub(crate) header_len: usize,
    /// Offset of the packet number from the start of the packet
    pub(crate) pn_pos: usize,
    pub(crate) packet_number: u64,
    pub(crate) path_id: PathId,
    pub(crate) header_key: Arc<dyn HeaderKey>,
    pub(crate) packet_key: Arc<dyn PacketKey>,
}

impl DeferredSeal {
    /// Protect the packet in place
    ///
    /// `buf` is the buffer the transmit holding this packet was written to.
    pub fn seal(&self, buf: &mut [u8]) {
        let packet = &mut buf[self.start..self.end];
        self.packet_key
            .encrypt(self.path_id, self.packet_number, packet, self.header_len);
        self.header_key.encrypt(self.pn_pos, packet);
    }
}

impl core::fmt::Debug for DeferredSeal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeferredSeal")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("packet_number", &self.packet_number)
            .field("path_id", &self.path_id)
            .finish_non_exhaustive()
    }
}

/// A key for signing with HMAC-based algorithms
pub trait HmacKey: Send + Sync {
    /// Method for signing a message
    fn sign(&self, data: &[u8], signature_out: &mut [u8]);
    /// Length of `sign`'s output
    fn signature_len(&self) -> usize;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// The trait for encrypting tokens that power retry packets and NEW_TOKEN frames.
pub trait HandshakeTokenKey: Send + Sync {
    /// Method for sealing a token in-place.
    ///
    /// The nonce doesn't need to be attached to the ciphertext,
    /// but the authentication tag is expected to be appended to `data`.
    fn seal(&self, token_nonce: u128, data: &mut Vec<u8>) -> Result<(), CryptoError>;
    /// Method for opening a sealed message `data` in-place.
    ///
    /// Returns the portion of `data` that contains the decrypted plaintext.
    fn open<'a>(&self, token_nonce: u128, data: &'a mut [u8]) -> Result<&'a [u8], CryptoError>;
}

/// Generic crypto errors
#[derive(Debug)]
pub struct CryptoError;

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub struct UnsupportedVersion;

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
