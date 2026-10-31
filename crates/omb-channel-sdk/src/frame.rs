//! Length-prefixed JSON frames: 4-byte big-endian length, then at most [`FRAME_MAX`] bytes of UTF-8 JSON.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::FRAME_MAX;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame_io")]
    Io(#[from] std::io::Error),
    #[error("frame_zero_length")]
    ZeroLength,
    #[error("frame_too_large")]
    TooLarge(usize),
    #[error("frame_utf8")]
    Utf8,
    #[error("frame_json")]
    Json,
    #[error("frame_duplicate_key")]
    DuplicateKey,
}

/// Reads one frame payload; `Ok(None)` only for a clean end of stream before the length prefix.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0; 4];
    let first = reader.read(&mut header).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[first..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(FrameError::ZeroLength);
    }
    if length > FRAME_MAX {
        return Err(FrameError::TooLarge(length));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.len() > FRAME_MAX {
        return Err(FrameError::TooLarge(payload.len()));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Rejects invalid UTF-8 and duplicate keys at any depth, then decodes `T`.
pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, FrameError> {
    let text = std::str::from_utf8(payload).map_err(|_| FrameError::Utf8)?;
    // The scan only raises a data error for a duplicate key; syntax and EOF errors are plain JSON errors.
    serde_json::from_str::<UniqueJson>(text).map_err(|error| {
        if error.is_data() {
            FrameError::DuplicateKey
        } else {
            FrameError::Json
        }
    })?;
    serde_json::from_str(text).map_err(|_| FrameError::Json)
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    serde_json::to_vec(value).map_err(|_| FrameError::Json)
}

// serde_json::Value would silently keep the last of two equal keys, so objects are scanned first.
struct UniqueJson;
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut keys = HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    map.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                while seq.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
