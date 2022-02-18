//! # Simple example
//!
//! ```no_run
//! use miio_proto::Device;
//!
//! fn main() {
//!     let rt = tokio::runtime::Runtime::new().expect("Async runtime");
//!     rt.block_on(async {
//!         let conn = Device::new(
//!             "192.168.1.1:54321",
//!             1234512345,
//!             [
//!                 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
//!                 0xee, 0xff,
//!             ],
//!         )
//!         .await
//!         .expect("Connect");
//!         conn.send_handshake().await.expect("Handshake");
//!         let (hello, _) = conn.recv().await.expect("Response");
//!
//!         conn.send(
//!             hello.stamp + 1,
//!             "{'method':'power','id':1,'params':['off']}",
//!         )
//!         .await
//!         .expect("Request");
//!     })
//! }
//! ```

#![warn(rust_2018_idioms)]
#![deny(missing_docs)]

use anyhow::Result;
use packed_struct::prelude::*;
use tokio::net::UdpSocket;

#[derive(PackedStruct, Debug, Clone)]
#[packed_struct(endian = "msb")]
/// Struct describes protocol message header
pub struct MessageHeader {
    /// Always 0x2131
    pub magic_number: u16,
    /// Packet length including the header itself (32 bytes)
    pub packet_length: u16,
    /// Some unknown bytes
    pub unknown: u32,
    /// Device ID
    pub device_id: u32,
    /// Incrementing timestamp as reported by device
    pub stamp: u32,
    /// Checksum. See protocol description.
    pub checksum: [u8; 16],
}

/// Connection holder
pub struct Device {
    /// Socket
    socket: std::sync::Arc<UdpSocket>,
    /// Device ID
    device_id: u32,
    /// Device token
    token: [u8; 16],
}

impl Device {
    /// Initializes new connection to specific MIIO device
    ///
    /// # Arguments
    ///
    /// * `address` — Device address in form "192.168.1.1:54321"
    /// * `device_id` — Device ID. Can be extracted from the response to handshake() call.
    /// * `token` — 16 bytes device token.
    pub async fn new(address: &str, device_id: u32, token: [u8; 16]) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(address).await?;

        let r = Self {
            socket: std::sync::Arc::new(socket),
            device_id,
            token,
        };
        Ok(r)
    }

    fn encode_payload(token: &[u8; 16], payload: &str) -> Vec<u8> {
        let key = md5::compute(token).to_vec();
        let mut iv_src = key.to_vec();
        iv_src.extend(token);
        let iv = md5::compute(iv_src).to_vec();

        use aes::Aes128;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};

        let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(&key, &iv).unwrap();

        cipher.encrypt_vec(payload.as_bytes())
    }

    fn decode_payload(token: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        let key = md5::compute(token).to_vec();
        let mut iv_src = key.to_vec();
        iv_src.extend(token);
        let iv = md5::compute(iv_src).to_vec();

        use aes::Aes128;
        use block_modes::block_padding::Pkcs7;
        use block_modes::{BlockMode, Cbc};

        let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(&key, &iv).unwrap();

        let mut buf = payload.to_vec();
        cipher.decrypt(&mut buf).unwrap().to_vec()
    }

    async fn send_raw(
        socket: std::sync::Arc<UdpSocket>,
        unknown: u32,
        device_id: u32,
        stamp: u32,
        token: &[u8; 16],
        payload: &str,
    ) -> Result<()> {
        let payload = if payload.is_empty() {
            Vec::new()
        } else {
            log::trace!("Plain payload: {:?}", payload);
            let payload = Self::encode_payload(token, payload);
            log::trace!("Encoded payload len={}: {:?}", payload.len(), payload);
            payload
        };

        let message = MessageHeader {
            magic_number: 0x2131,
            packet_length: (payload.len() + 32) as u16,
            unknown,
            device_id,
            stamp,
            checksum: *token,
        };

        let mut packet = message.pack_to_vec()?.pack_to_vec()?;
        packet.extend(&payload);
        let checksum = md5::compute(packet);

        let message = MessageHeader {
            checksum: *checksum,
            ..message
        };

        let mut packet = message.pack()?.pack_to_vec()?;
        packet.extend(&payload);
        log::trace!(
            "Sending packet. Total length {} bytes, payload length {}. Raw packet: {:?}",
            packet.len(),
            payload.len(),
            packet
        );
        let sent = socket.send(&packet).await?;
        log::debug!("Sent {} bytes", sent);

        Ok(())
    }

    /// Reads and returns packet from MIIO device.
    /// Returns tuple of two values:
    /// * Message header
    /// * Decoded payload
    pub async fn recv(&self) -> Result<(MessageHeader, String)> {
        let mut buf = [0_u8; 65535];
        self.socket.recv(&mut buf).await?;
        let mut hdr: [u8; 32] = Default::default();
        hdr.copy_from_slice(&buf[..32]);
        let resp = MessageHeader::unpack(&hdr)?;
        log::trace!("Got header: {:?}", resp);
        let payload = &buf[32..resp.packet_length as usize];
        log::trace!("Got payload len={}: {:?}", payload.len(), payload);
        let payload = Self::decode_payload(&self.token, payload);
        let payload = std::str::from_utf8(&payload)?;
        if !payload.is_empty() {
            log::trace!("Decoded payload: {}", payload);
        }

        Ok((resp, payload.to_string()))
    }

    /// Sends handshake packet to MIIO device.
    pub async fn send_handshake(&self) -> Result<()> {
        Self::send_raw(
            self.socket.clone(),
            0xffffffff,
            0xffffffff,
            0xffffffff,
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ],
            "",
        )
        .await
    }

    /// Sends JSON payload to MIIO device.
    ///
    /// # Arguments
    ///
    /// * `stamp` — Continuously increasing counter.
    /// * `payload` — JSON string.
    pub async fn send(&self, stamp: u32, payload: &str) -> Result<()> {
        Self::send_raw(
            self.socket.clone(),
            0,
            self.device_id,
            stamp,
            &self.token,
            payload,
        )
        .await
    }
}
