use bytes::{BufMut, Bytes, BytesMut};
use flate2::{Decompress, FlushDecompress};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: WsOpcode,
    pub payload: Bytes,
}

impl WsFrame {
    pub fn is_text(&self) -> bool {
        self.opcode == WsOpcode::Text
    }

    pub fn is_binary(&self) -> bool {
        self.opcode == WsOpcode::Binary
    }

    pub fn is_continuation(&self) -> bool {
        self.opcode == WsOpcode::Continuation
    }

    pub fn text(&self) -> Option<&str> {
        if self.opcode == WsOpcode::Text {
            std::str::from_utf8(&self.payload).ok()
        } else {
            None
        }
    }

    pub fn set_text(&mut self, data: &str) {
        self.opcode = WsOpcode::Text;
        self.payload = Bytes::copy_from_slice(data.as_bytes());
        self.rsv1 = false;
        self.rsv2 = false;
        self.rsv3 = false;
    }

    pub fn set_binary(&mut self, data: impl Into<Bytes>) {
        self.opcode = WsOpcode::Binary;
        self.payload = data.into();
        self.rsv1 = false;
        self.rsv2 = false;
        self.rsv3 = false;
    }

    pub fn decompress_with(&self, decompressor: &mut Decompress) -> Option<Bytes> {
        if !self.rsv1 {
            return Some(self.payload.clone());
        }

        let mut data = self.payload.to_vec();
        // Append 0x00 0x00 0xff 0xff tail if fin is true (end of message)
        // permessage-deflate strips this tail from the output.
        if self.fin {
            data.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        }

        let mut out = Vec::with_capacity(self.payload.len() * 3);
        match decompressor.decompress_vec(&data, &mut out, FlushDecompress::Sync) {
            Ok(_) => Some(Bytes::from(out)),
            Err(e) => {
                log::error!("Decompression error: {:?}", e);
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsParseResult {
    Ok,
    Incomplete,
    Invalid,
}

pub fn parse_ws_frames(buffer: &mut BytesMut, frames: &mut Vec<WsFrame>) -> WsParseResult {
    // Pre-allocate capacity for frames to reduce reallocations
    if frames.capacity() == 0 {
        frames.reserve(16);
    }

    loop {
        let buffer_len = buffer.len();
        if buffer_len < 2 {
            return if frames.is_empty() {
                WsParseResult::Incomplete
            } else {
                WsParseResult::Ok
            };
        }

        let b0 = buffer[0];
        let b1 = buffer[1];
        let fin = (b0 & 0x80) != 0;
        let rsv1 = (b0 & 0x40) != 0;
        let rsv2 = (b0 & 0x20) != 0;
        let rsv3 = (b0 & 0x10) != 0;
        let opcode = match b0 & 0x0f {
            0x0 => WsOpcode::Continuation,
            0x1 => WsOpcode::Text,
            0x2 => WsOpcode::Binary,
            0x8 => WsOpcode::Close,
            0x9 => WsOpcode::Ping,
            0xA => WsOpcode::Pong,
            v => WsOpcode::Other(v),
        };
        let masked = (b1 & 0x80) != 0;
        let mut len = (b1 & 0x7f) as u64;
        let mut offset = 2usize;

        if len == 126 {
            if buffer_len < 4 {
                return if frames.is_empty() {
                    WsParseResult::Incomplete
                } else {
                    WsParseResult::Ok
                };
            }
            len = u16::from_be_bytes([buffer[2], buffer[3]]) as u64;
            offset = 4;
        } else if len == 127 {
            if buffer_len < 10 {
                return if frames.is_empty() {
                    WsParseResult::Incomplete
                } else {
                    WsParseResult::Ok
                };
            }
            len = u64::from_be_bytes([
                buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8],
                buffer[9],
            ]);
            offset = 10;
        }

        let len_usize = match usize::try_from(len) {
            Ok(v) => v,
            Err(_) => return WsParseResult::Invalid,
        };

        let mask_key = if masked {
            if buffer_len < offset + 4 {
                return if frames.is_empty() {
                    WsParseResult::Incomplete
                } else {
                    WsParseResult::Ok
                };
            }
            let key = [
                buffer[offset],
                buffer[offset + 1],
                buffer[offset + 2],
                buffer[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        if buffer_len < offset + len_usize {
            return if frames.is_empty() {
                WsParseResult::Incomplete
            } else {
                WsParseResult::Ok
            };
        }

        let mut data = buffer.split_to(offset + len_usize);
        let _header = data.split_to(offset);

        let payload = if let Some(key) = mask_key {
            let mut payload_vec = data.to_vec();
            apply_mask(&mut payload_vec, key);
            Bytes::from(payload_vec)
        } else {
            data.freeze()
        };

        if opcode == WsOpcode::Continuation {
            if let Some(last_frame) = frames.last_mut() {
                let mut new_payload =
                    BytesMut::with_capacity(last_frame.payload.len() + payload.len());
                new_payload.extend_from_slice(&last_frame.payload);
                new_payload.extend_from_slice(&payload);
                last_frame.payload = new_payload.freeze();
                last_frame.fin = fin;
                continue;
            } else {
                return WsParseResult::Invalid;
            }
        }

        frames.push(WsFrame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            payload,
        });
    }
}

pub fn encode_ws_frame(frame: &WsFrame, mask_key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_ws_frame_into(frame, mask_key, &mut out);
    out
}

pub fn encode_ws_frame_into(frame: &WsFrame, mask_key: Option<[u8; 4]>, out: &mut impl BufMut) {
    let opcode = match frame.opcode {
        WsOpcode::Continuation => 0x0,
        WsOpcode::Text => 0x1,
        WsOpcode::Binary => 0x2,
        WsOpcode::Close => 0x8,
        WsOpcode::Ping => 0x9,
        WsOpcode::Pong => 0xA,
        WsOpcode::Other(v) => v & 0x0f,
    };
    let mut b0 = if frame.fin { 0x80 } else { 0x00 } | opcode;
    if frame.rsv1 {
        b0 |= 0x40;
    }
    if frame.rsv2 {
        b0 |= 0x20;
    }
    if frame.rsv3 {
        b0 |= 0x10;
    }
    out.put_u8(b0);

    let masked = mask_key.is_some();
    let payload_len = frame.payload.len() as u64;
    if payload_len <= 125 {
        out.put_u8((if masked { 0x80 } else { 0x00 }) | payload_len as u8);
    } else if payload_len <= u16::MAX as u64 {
        out.put_u8(if masked { 0x80 | 126 } else { 126 });
        out.put_slice(&(payload_len as u16).to_be_bytes());
    } else {
        out.put_u8(if masked { 0x80 | 127 } else { 127 });
        out.put_slice(&payload_len.to_be_bytes());
    }

    if let Some(key) = mask_key {
        out.put_slice(&key);
        let mut masked_payload = frame.payload.to_vec();
        apply_mask(&mut masked_payload, key);
        out.put_slice(&masked_payload);
    } else {
        out.put_slice(&frame.payload);
    }
}

pub fn mask_key_from_time() -> [u8; 4] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    [
        (nanos & 0xff) as u8,
        ((nanos >> 8) & 0xff) as u8,
        ((nanos >> 16) & 0xff) as u8,
        ((nanos >> 24) & 0xff) as u8,
    ]
}

fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[idx % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_encode_text_frame() {
        let frame = WsFrame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WsOpcode::Text,
            payload: Bytes::from_static(b"hello"),
        };
        let mask_key = [1, 2, 3, 4];
        let encoded = encode_ws_frame(&frame, Some(mask_key));
        let mut buffer = BytesMut::from(encoded.as_slice());
        let mut frames = Vec::new();
        let result = parse_ws_frames(&mut buffer, &mut frames);
        assert_eq!(result, WsParseResult::Ok);
        assert!(buffer.is_empty());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], frame);
    }

    #[test]
    fn parse_incomplete_frame() {
        let mut buffer = BytesMut::from(&[0x81, 0x85, 1, 2, 3][..]);
        let mut frames = Vec::new();
        let result = parse_ws_frames(&mut buffer, &mut frames);
        assert_eq!(result, WsParseResult::Incomplete);
        assert!(frames.is_empty());
    }
    #[test]
    fn test_ws_frame_helpers() {
        let mut frame = WsFrame {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WsOpcode::Binary,
            payload: Bytes::from_static(b"binary"),
        };

        assert!(frame.is_binary());
        assert!(!frame.is_text());
        assert_eq!(frame.text(), None);

        frame.set_text("hello");
        assert!(frame.is_text());
        assert!(!frame.is_binary());
        assert_eq!(frame.text(), Some("hello"));
        assert_eq!(frame.payload, Bytes::from_static(b"hello"));

        frame.set_binary(vec![1, 2, 3]);
        assert!(frame.is_binary());
        assert_eq!(frame.payload, Bytes::from_static(b"\x01\x02\x03"));
    }
}
