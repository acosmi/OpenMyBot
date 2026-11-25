use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use openbot_account_bridge::frame::{FrameError, decode, encode, read_frame, write_frame};
use openbot_account_bridge::protocol::{HostFrame, PluginFrame};
use openbot_account_bridge::{FRAME_MAX, PROTOCOL, PROTOCOL_FIXTURE_DIGEST};
use serde_json::Value;
use sha2::{Digest, Sha256};

const HOST_FRAMES: [&str; 12] = [
    "hello",
    "login_start",
    "login_poll",
    "login_cancel",
    "credential_load",
    "refresh",
    "models",
    "usage",
    "infer",
    "infer_cancel",
    "revoke",
    "shutdown",
];
const PLUGIN_FRAMES: [&str; 11] = [
    "hello_ok",
    "login_progress",
    "login_result",
    "refresh_result",
    "revoke_result",
    "credential_rejected",
    "models_result",
    "usage_result",
    "infer_event",
    "infer_end",
    "error",
];

/// The fixture directory named by the protocol number, so a new number needs a new directory.
fn fixture_root() -> PathBuf {
    let number = PROTOCOL.rsplit('/').next().unwrap();
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/account-bridge")
        .join(format!("protocol-{number}"))
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    files
}

/// Decodes every fixture of `dir` as `T`, checks that encoding gives back the same JSON and returns
/// the frame types covered.
fn decode_all<T>(dir: &str) -> BTreeSet<String>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut types = BTreeSet::new();
    for path in files(&fixture_root().join(dir)) {
        let bytes = fs::read(&path).unwrap();
        let frame: T = decode(&bytes).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        let wire: Value = serde_json::from_slice(&encode(&frame).unwrap()).unwrap();
        assert_eq!(
            wire,
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            "{path:?}"
        );
        types.insert(wire["type"].as_str().unwrap().to_owned());
    }
    types
}

#[test]
fn every_fixture_decodes_and_every_frame_type_has_one() {
    let host = decode_all::<HostFrame>("host-to-plugin");
    assert_eq!(host, HOST_FRAMES.map(str::to_owned).into());
    let plugin = decode_all::<PluginFrame>("plugin-to-host");
    assert_eq!(plugin, PLUGIN_FRAMES.map(str::to_owned).into());
}

#[test]
fn negative_fixtures_are_rejected() {
    let negative = fixture_root().join("negative");
    let names: Vec<String> = files(&negative)
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        [
            "host-credential_load-duplicate-key.json",
            "host-hello-wrong-protocol.json",
            "host-infer-unknown-field.json",
        ]
    );

    let duplicate = fs::read(negative.join(&names[0])).unwrap();
    assert!(matches!(
        decode::<HostFrame>(&duplicate),
        Err(FrameError::DuplicateKey)
    ));

    let wrong_protocol = fs::read_to_string(negative.join(&names[1])).unwrap();
    assert!(matches!(
        decode::<HostFrame>(wrong_protocol.as_bytes()),
        Err(FrameError::Json)
    ));
    // The protocol name is the only defect of that fixture.
    let corrected = wrong_protocol.replace("wrokbot-account-bridge/2", PROTOCOL);
    assert!(matches!(
        decode::<HostFrame>(corrected.as_bytes()),
        Ok(HostFrame::Hello { .. })
    ));

    let unknown = fs::read(negative.join(&names[2])).unwrap();
    assert!(matches!(
        decode::<HostFrame>(&unknown),
        Err(FrameError::Json)
    ));
}

#[tokio::test]
async fn frame_over_one_mebibyte_is_rejected() {
    // Only the length prefix exists: a body read would fail with an I/O error instead.
    let header = ((FRAME_MAX + 1) as u32).to_be_bytes().to_vec();
    let error = read_frame(&mut Cursor::new(header)).await.unwrap_err();
    assert!(matches!(error, FrameError::TooLarge(length) if length == FRAME_MAX + 1));

    let mut sink = Vec::new();
    let error = write_frame(&mut sink, &vec![b' '; FRAME_MAX + 1])
        .await
        .unwrap_err();
    assert!(matches!(error, FrameError::TooLarge(length) if length == FRAME_MAX + 1));
    assert!(sink.is_empty());

    let mut wire = (FRAME_MAX as u32).to_be_bytes().to_vec();
    wire.resize(4 + FRAME_MAX, b' ');
    let read = read_frame(&mut Cursor::new(wire)).await.unwrap().unwrap();
    assert_eq!(read.len(), FRAME_MAX);
}

#[test]
fn fixture_directory_digest_is_pinned_with_the_protocol_name() {
    let root = fixture_root();
    let mut paths = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for path in files(&dir) {
            if path.is_dir() {
                pending.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    let mut listing: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            let relative = path.strip_prefix(&root).unwrap().to_str().unwrap();
            let digest = Sha256::digest(fs::read(path).unwrap());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            (relative.replace('\\', "/"), hex)
        })
        .collect();
    listing.sort();
    let canonical: String = listing
        .iter()
        .map(|(path, hex)| format!("{hex}  {path}\n"))
        .collect();
    let digest = Sha256::digest(canonical.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        (PROTOCOL, hex.as_str()),
        ("wrokbot-account-bridge/1", PROTOCOL_FIXTURE_DIGEST),
        "a frame shape changed: bump the protocol number, add a new fixture directory and pin its digest"
    );
}
