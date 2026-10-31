//! 纯 AEAD 变换：v1 兼容读（[`decrypt_v1`]）与 v2 的封装 / 解封（[`seal_v2`] / [`open_v2`]）。
//!
//! # 三档密钥长度的分派，以及为什么 192 位不是"没有对应类型"
//!
//! `aes-gcm 0.10.3` 只导出了两个别名（实测：`grep 'pub type Aes' lib.rs` 命中
//! `Aes128Gcm = AesGcm<Aes128, U12>` 与 `Aes256Gcm = AesGcm<Aes256, U12>` 两条），确实**没有**
//! `Aes192Gcm`。但同一个 `lib.rs` 里有 `pub use aes;` —— `AesGcm<aes::Aes192, U12>` 是编得
//! 出来的，本模块的 [`Aes192Gcm`] 就是这一行。
//!
//! 这不是为了凑齐三档而凑：上游**接受 192 位密钥**。实测（用上游 `server/src/credentials.ts`
//! 的原始字节在 Bun 1.3.11 上跑 `encryptSecret` + `decryptSecret`，24 字节 `KEY_ENCRYPTION_KEY`）
//! round-trip 成功；同一次探测里 20 字节密钥被 WebCrypto 拒绝，报 `DataError` —— 那是这条
//! 探测"确实能说不"的正向对照。也就是说，一个把 `KEY_ENCRYPTION_KEY` 配成 24 字节的部署，
//! 数据在上游是能读的；Rust 侧若拒绝 192 位，那个部署就**永远迁不过来**。
//!
//! "兼容读"这条要求的判据只有一个：**上游写得出来的，我们必须读得出来。** 所以三档全支持，
//! 其余长度一律 [`VaultError::KeyLength`]（在 [`super::key::WrappingKey::from_bytes`] 就拒了），
//! 绝不截断、补零或"当成最接近的那一档"。
//!
//! # v1 与 v2 的差别只有两处，但都是要害
//!
//! | | v1（上游） | v2（本项目） |
//! | --- | --- | --- |
//! | 密钥 | `KEY_ENCRYPTION_KEY` **直接**加密每条记录 | 每记录随机 DEK，DEK 由 KEK 包装 |
//! | AAD | **无** | 绑定 §6.4 六元组（[`super::binding`]） |
//!
//! 没有 AAD 意味着 v1 密文可以**整段搬家**：把 A 租户某条模型密钥的密文复制进 B 租户另一行，
//! 只要两边同一把 `KEY_ENCRYPTION_KEY`（单部署内恒成立），解密照样成功。v2 关掉的就是这个。
//!
//! 每记录一个 DEK 关掉的是另一件事：nonce 复用的**爆炸半径**。AES-GCM 在同一把密钥下重用
//! nonce 会同时丢掉机密性与完整性；v1 全库共用一把密钥，随机 12 字节 IV 在生日界附近就开始
//! 有碰撞概率，而且一次碰撞牵连的是**全库**。v2 的 record nonce 只需要在一把只用一次的 DEK
//! 下唯一 —— 这是构造上的降级，不是"我们会小心一点"。

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, AeadCore, AeadInPlace, KeyInit, Payload, consts::U12};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};

use super::binding::RecordBinding;
use super::envelope::{EnvelopeV1, EnvelopeV2};
use super::error::VaultError;
use super::key::{DataKey, Nonce, TAG_BYTES, WrappingKey};
use super::secret::SecretBytes;

/// `aes-gcm 0.10.3` 没有导出的那个别名，理由与必要性见模块文档。
type Aes192Gcm = AesGcm<aes_gcm::aes::Aes192, U12>;

/// 用 v1 的规则解一段上游信封：**无 AAD**，IV 12 字节，tag 追加在密文尾部。
///
/// 三条都是实测出来的，不是按 AES-GCM 的一般惯例推的 —— 证据表在 [`super::envelope`] 的
/// 模块文档里。
///
/// # Errors
///
/// - [`VaultError::Decrypt`]：认证失败（密钥错 / 密文被改过，两者不可分辨）。
/// - [`VaultError::KeyLength`]：包装密钥长度不是 16 / 24 / 32。正常路径上
///   [`WrappingKey::from_bytes`] 已经拒过一次，这里是兜底。
pub fn decrypt_v1(key: &WrappingKey, envelope: &EnvelopeV1) -> Result<SecretBytes, VaultError> {
    let plaintext = aes_gcm_decrypt(key.material(), envelope.iv(), b"", envelope.ciphertext())?;
    Ok(SecretBytes::new(plaintext))
}

/// 用 KEK 包装一个 DEK。AAD = [`RecordBinding::data_key_aad`]。
///
/// # Errors
///
/// [`VaultError::KeyLength`] / [`VaultError::PlaintextTooLarge`]，见 [`aes_gcm_encrypt`]。
pub fn wrap_data_key(
    kek: &WrappingKey,
    binding: &RecordBinding,
    dek_nonce: Nonce,
    dek: &DataKey,
) -> Result<Vec<u8>, VaultError> {
    aes_gcm_encrypt(
        kek.material(),
        dek_nonce,
        &binding.data_key_aad(),
        dek.material(),
    )
}

/// 解开一个被 KEK 包装的 DEK。
///
/// # Errors
///
/// - [`VaultError::Decrypt`]：认证失败。**包括** binding 与包装时不一致的情形 —— 这正是
///   AAD 要拦的那件事。
/// - [`VaultError::DataKeyLength`]：解出来的东西长度不是 32。它意味着这段密文虽然通过了
///   认证，但装的不是一把 DEK —— 只有在 AAD 域分隔失效时才可能发生，所以它同时是
///   [`super::binding`] 那条域分隔的**运行期兜底**。
pub fn unwrap_data_key(
    kek: &WrappingKey,
    binding: &RecordBinding,
    dek_nonce: Nonce,
    wrapped: &[u8],
) -> Result<DataKey, VaultError> {
    let material = aes_gcm_decrypt(kek.material(), dek_nonce, &binding.data_key_aad(), wrapped)?;
    DataKey::from_bytes(material)
}

/// 封装一条 v2 记录：包装 DEK，再用 DEK 加密明文，AAD 绑定六元组。
///
/// # 为什么 DEK 与两个 nonce 都是参数
///
/// 领域层不生成随机数（[`super::key`] 的模块文档）。这三样必须由 infra 用 OS CSPRNG 铸好
/// 传进来，**且 `record_nonce` 与 `dek_nonce` 在同一把密钥下必须唯一** —— 后半句本模块
/// 验证不了，见交付报告。
///
/// # Errors
///
/// 见 [`aes_gcm_encrypt`]。
pub fn seal_v2(
    kek: &WrappingKey,
    dek: &DataKey,
    binding: &RecordBinding,
    dek_nonce: Nonce,
    record_nonce: Nonce,
    plaintext: &[u8],
) -> Result<EnvelopeV2, VaultError> {
    let wrapped_dek = wrap_data_key(kek, binding, dek_nonce, dek)?;
    let ciphertext = aes_gcm_encrypt(
        dek.material(),
        record_nonce,
        &binding.record_aad(),
        plaintext,
    )?;
    Ok(EnvelopeV2::new(
        binding.key_version(),
        dek_nonce,
        wrapped_dek,
        record_nonce,
        ciphertext,
    ))
}

/// 解开一条 v2 记录。
///
/// # 密文不许自述身份
///
/// 进 AAD 的 `key_version` 取自 **`binding`**，不是取自信封。信封里那个字段只是给调用方
/// **找钥匙**用的线索，两者不一致即 [`VaultError::KeyVersionMismatch`]。
///
/// 反过来做（信任信封里的版本号）会开一个降级洞：攻击者把行里的 `key_version` 改成一个
/// 已泄漏的旧版本，就能诱导我们用弱密钥去解 —— 而 AAD 绑定的全部意义正是不让密文自己说
/// 自己是谁。
///
/// # Errors
///
/// - [`VaultError::KeyVersionMismatch`]：见上。这是唯一一条在密码学运算**之前**判定的
///   拒绝，所以它可分辨。
/// - [`VaultError::Decrypt`]：认证失败（KEK 错、binding 六元组任一项对不上、密文被改过）。
/// - [`VaultError::DataKeyLength`]：见 [`unwrap_data_key`]。
pub fn open_v2(
    kek: &WrappingKey,
    binding: &RecordBinding,
    envelope: &EnvelopeV2,
) -> Result<SecretBytes, VaultError> {
    if envelope.key_version() != binding.key_version() {
        return Err(VaultError::KeyVersionMismatch);
    }
    let dek = unwrap_data_key(kek, binding, envelope.dek_nonce(), envelope.wrapped_dek())?;
    let plaintext = aes_gcm_decrypt(
        dek.material(),
        envelope.nonce(),
        &binding.record_aad(),
        envelope.ciphertext(),
    )?;
    Ok(SecretBytes::new(plaintext))
}

/// 按密钥长度分派的 AES-GCM 加密。
///
/// # Errors
///
/// - [`VaultError::KeyLength`]：长度不是 16 / 24 / 32。
/// - [`VaultError::PlaintextTooLarge`]：明文超过 GCM 单条消息上限。这是加密侧唯一现实存在的
///   失败模式，理由见 [`VaultError::PlaintextTooLarge`]。
pub(crate) fn aes_gcm_encrypt(
    key: &[u8],
    nonce: Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    match key.len() {
        16 => encrypt_with::<Aes128Gcm>(key, nonce, aad, plaintext),
        24 => encrypt_with::<Aes192Gcm>(key, nonce, aad, plaintext),
        32 => encrypt_with::<Aes256Gcm>(key, nonce, aad, plaintext),
        _ => Err(VaultError::KeyLength),
    }
}

/// 按密钥长度分派的 AES-GCM 解密。
///
/// # Errors
///
/// [`VaultError::KeyLength`] / [`VaultError::CiphertextTooShort`] / [`VaultError::Decrypt`]。
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    nonce: Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if ciphertext.len() < TAG_BYTES {
        return Err(VaultError::CiphertextTooShort);
    }
    match key.len() {
        16 => decrypt_with::<Aes128Gcm>(key, nonce, aad, ciphertext),
        24 => decrypt_with::<Aes192Gcm>(key, nonce, aad, ciphertext),
        32 => decrypt_with::<Aes256Gcm>(key, nonce, aad, ciphertext),
        _ => Err(VaultError::KeyLength),
    }
}

/// Detached AES-256-GCM for the independent capture codec's single owned frame buffer.
/// This is crate-private: the codec fixes the purpose, nonce sequence and authenticated headers.
pub(crate) fn whole_pg_seal_in_place(
    key: &SecretBytes,
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| VaultError::KeyLength)?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer)
        .map_err(|_| VaultError::PlaintextTooLarge)?;
    Ok(tag.into())
}

pub(crate) fn whole_pg_open_in_place(
    key: &SecretBytes,
    nonce: &[u8; 12],
    aad: &[u8],
    tag: &[u8; 16],
    buffer: &mut [u8],
) -> Result<(), VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key.expose()).map_err(|_| VaultError::KeyLength)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            buffer,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| VaultError::Decrypt)
}

/// 三档共用的加密实现。泛型而不是抄三遍 —— 抄三遍就是三份各自漂移的机会。
fn encrypt_with<C>(
    key: &[u8],
    nonce: Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError>
where
    C: KeyInit + Aead + AeadCore<NonceSize = U12>,
{
    let cipher = C::new_from_slice(key).map_err(|_| VaultError::KeyLength)?;
    cipher
        .encrypt(
            GenericArray::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::PlaintextTooLarge)
}

/// 三档共用的解密实现。
fn decrypt_with<C>(
    key: &[u8],
    nonce: Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError>
where
    C: KeyInit + Aead + AeadCore<NonceSize = U12>,
{
    let cipher = C::new_from_slice(key).map_err(|_| VaultError::KeyLength)?;
    cipher
        .decrypt(
            GenericArray::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::Decrypt)
}

#[cfg(test)]
mod tests {
    use openbot_contracts::ids::{ActorId, TenantId};

    use super::super::binding::{KeyVersion, SecretId, SecretKind, SecretPrincipal, ServiceId};
    use super::super::key::{DATA_KEY_BYTES, NONCE_BYTES};
    use super::*;

    /// 测试里把十六进制串解成字节。`hex_literal` 不在本 crate 的依赖表里，而为了几条测试
    /// 向量去改 `Cargo.toml` 不值得。
    fn hex(input: &str) -> Vec<u8> {
        assert!(input.len().is_multiple_of(2), "十六进制串必须是偶数长度");
        (0..input.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&input[index..index + 2], 16).expect("合法十六进制"))
            .collect()
    }

    fn nonce_from_hex(input: &str) -> Nonce {
        Nonce::from_slice(&hex(input)).expect("测试向量的 nonce 恒为 12 字节")
    }

    // ───────────────────────── 第一层证据：NIST CAVS 已知答案 ─────────────────────────
    //
    // 来源是本机 `~/.cargo/registry/src/index.crates.io-*/aes-gcm-0.10.3/tests/aes256gcm.rs`
    // 与 `aes128gcm.rs`，文件头逐字写着「NIST CAVS vectors …… From: `gcmEncryptExtIV256.rsp`」。
    // 抄的是**本机可复核的文件**，不是记忆里的数字 —— 路径给出来就是为了让复核者能自己 diff。
    //
    // 这一层证明的是：本模块对 `aes-gcm` 的**用法**（nonce 怎么给、AAD 怎么给、tag 在哪一端）
    // 与 NIST 公布的答案逐字节一致。它不证明 v1 信封的**格式**读对了 —— 那是第二层的事。

    /// AES-256-GCM，带 AAD，明文与密文都非空。
    #[test]
    fn aes256_matches_the_nist_cavs_known_answer() {
        let key = hex("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b");
        let nonce = nonce_from_hex("ac93a1a6145299bde902f21a");
        let plaintext = hex("2d71bcfa914e4ac045b2aa60955fad24");
        let aad = hex("1e0889016f67601c8ebea4943bc23ad6");
        let expected = hex("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab");

        let produced =
            aes_gcm_encrypt(&key, nonce, &aad, &plaintext).expect("CAVS 向量必须加得出来");
        assert_eq!(produced, expected, "密文‖tag 必须与 CAVS 逐字节相同");

        let recovered = aes_gcm_decrypt(&key, nonce, &aad, &expected).expect("CAVS 向量必须解得开");
        assert_eq!(recovered, plaintext);

        // 负向对照：AAD 改一个 bit，认证必须失败。没有这一条，上面两条在
        // "AAD 根本没被喂进去"的世界里同样通过。
        let mut tampered_aad = aad.clone();
        tampered_aad[0] ^= 0x01;
        assert_eq!(
            aes_gcm_decrypt(&key, nonce, &tampered_aad, &expected).unwrap_err(),
            VaultError::Decrypt
        );
    }

    /// AES-128-GCM，同一组判据。
    #[test]
    fn aes128_matches_the_nist_cavs_known_answer() {
        let key = hex("c939cc13397c1d37de6ae0e1cb7c423c");
        let nonce = nonce_from_hex("b3d8cc017cbb89b39e0f67e2");
        let plaintext = hex("c3b3c41f113a31b73d9a5cd432103069");
        let aad = hex("24825602bd12a984e0092d3e448eda5f");
        let expected = hex("93fe7d9e9bfd10348a5606e5cafa73540032a1dc85f1c9786925a2e71d8272dd");

        assert_eq!(
            aes_gcm_encrypt(&key, nonce, &aad, &plaintext).expect("CAVS 向量必须加得出来"),
            expected
        );
        assert_eq!(
            aes_gcm_decrypt(&key, nonce, &aad, &expected).expect("CAVS 向量必须解得开"),
            plaintext
        );
    }

    // ───────────────── 第二层证据：上游产出的真信封（跨语言互操作实测） ─────────────────
    //
    // 下面五条 `UPSTREAM_*` 常量不是手工构造的，是本轮把 `server/src/credentials.ts`
    // （commit 891df72f1827454d8b353d108fe5dd2313b7e30d，sha256
    // 407baae15245ff6376caa7978f2e74307c02181ea2abd8d9e9c83c4d2fe63cee）**逐字节复制**到一个
    // 只放依赖桩的目录，用 Bun 1.3.11 直接执行 `encryptSecret` 跑出来的。加密那一侧是上游
    // 自己的代码，本项目一行都没参与。
    //
    // 密钥是可复现的定值：KEY_N 的第 i 字节 = i（N = 16 / 24 / 32），base64 分别是
    // `AAECAwQFBgcICQoLDA0ODw==` / `AAECAwQFBgcICQoLDA0ODxAREhMUFRYX` /
    // `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`。它们是测试密钥，不是秘密。

    /// 依序递增的定值密钥：第 i 个字节 = i。
    fn counting_key(length: usize) -> WrappingKey {
        let material: Vec<u8> = (0..length)
            .map(|index| u8::try_from(index).expect("长度不超过 32"))
            .collect();
        WrappingKey::from_bytes(material).expect("16 / 24 / 32 都是合法长度")
    }

    /// AES-256、ASCII 明文。
    const UPSTREAM_AES256_ASCII: &str = "{\"version\":1,\"iv\":\"szoErpoKzwcaMoCm\",\"ciphertext\":\"knQI9icpTynm62CW0RlhMHtfOJ7ia4MnIEcPm5lnl3qD2MGAgsA=\"}";
    /// AES-256、**空**明文。密文恰好 16 字节 = 只有 tag。
    const UPSTREAM_AES256_EMPTY: &str =
        "{\"version\":1,\"iv\":\"GE/YZwAgox6TKBkD\",\"ciphertext\":\"N0I1del1g4F973suhnLSeg==\"}";
    /// AES-256、含非 ASCII 与一个**内嵌 NUL** 的明文。
    const UPSTREAM_AES256_UTF8: &str = "{\"version\":1,\"iv\":\"hStAoU0i076UOzEq\",\"ciphertext\":\"R3fFjTMiA3R9e/vutf7qJakiColhep/27AdLk4+n8ajMbRSbPYoHsXqfv438bHR/L4+hkfw=\"}";
    /// AES-256、明文本身是一段 JSON（`sso_providers.oidc_config` 的形状）。
    const UPSTREAM_AES256_JSON: &str = "{\"version\":1,\"iv\":\"RbnF75b/vSNFLzAI\",\"ciphertext\":\"ZaajxMXqIbEcE+BfoBm8ChBL0AMlHNv/f5vN8eKHLEu4NK+4K4bY2/LjPjbybf9ckN5pMe/RLw==\"}";
    /// AES-128。
    const UPSTREAM_AES128: &str = "{\"version\":1,\"iv\":\"lNvnNxtcrsqsjHsM\",\"ciphertext\":\"zIE9tP5O8Pjz5JeztjqCY8HDZk/HpRrheMwJgaN6fSNR6Mr6qcw=\"}";
    /// AES-256、明文含 **4 字节 UTF-8**：`U+1F511` 钥匙、一个 ZWJ 序列、以及星光平面的
    /// `U+1D11E`。39 字节明文 → 55 字节密文（+16 tag）。
    ///
    /// 补这一条的理由：前面那条 UTF-8 样本最宽只有 3 字节（`U+2713`）。多字节边界上出错的
    /// 实现通常在 3 字节上是对的、4 字节上才裂 —— 不覆盖 4 字节等于没覆盖多字节。
    const UPSTREAM_AES256_EMOJI: &str = "{\"version\":1,\"iv\":\"JItN1Oxw73CJcz72\",\"ciphertext\":\"5IKdBSL6kcpasDj0pThnu708HlNFJ3T1Ep+Wr0+VeD/o5plQFAuCHSrxjObM9DA3OSEdeaIPWA==\"}";

    /// AES-**192**。上游接受 24 字节密钥（实测 round-trip 成功），所以我们必须读得出来。
    const UPSTREAM_AES192: &str = "{\"version\":1,\"iv\":\"WD6AI/FxGQHFbdEB\",\"ciphertext\":\"N1wBDPeDHORCa03vbGlGDo8mK3yxSzrGY1yDCg==\"}";

    /// 解开上游真信封 —— 三档密钥长度各至少一条。
    ///
    /// 这是本模块最重的一条证据：**加密方是上游的 TypeScript，解密方是这里的 Rust。**
    #[test]
    fn decrypts_envelopes_produced_by_upstream_typescript() {
        let key256 = counting_key(32);
        let key192 = counting_key(24);
        let key128 = counting_key(16);

        let cases: [(&WrappingKey, &str, &[u8]); 6] = [
            (
                &key256,
                UPSTREAM_AES256_ASCII,
                b"sk-test-model-key-0001".as_slice(),
            ),
            (&key256, UPSTREAM_AES256_EMPTY, b"".as_slice()),
            (
                &key256,
                UPSTREAM_AES256_UTF8,
                "刷新令牌 refresh_token ✓ \u{0} tail".as_bytes(),
            ),
            (
                &key256,
                UPSTREAM_AES256_JSON,
                br#"{"clientId":"abc","clientSecret":"shh"}"#.as_slice(),
            ),
            (
                &key128,
                UPSTREAM_AES128,
                b"sk-test-model-key-0001".as_slice(),
            ),
            (&key192, UPSTREAM_AES192, b"aes192 probe".as_slice()),
        ];

        for (key, column, expected) in cases {
            let envelope = EnvelopeV1::parse(column).expect("上游真信封必须解析得开");
            let plaintext = decrypt_v1(key, &envelope)
                .unwrap_or_else(|error| panic!("上游真信封解密失败（{}）：{column}", error.code()));
            assert_eq!(plaintext.expose(), expected, "明文对不上：{column}");
        }
    }

    /// 内嵌 NUL 的明文逐字节相等 —— 证明这条链路上没有任何一处把明文当 C 字符串截断。
    #[test]
    fn upstream_plaintext_with_embedded_nul_survives_byte_for_byte() {
        let envelope = EnvelopeV1::parse(UPSTREAM_AES256_UTF8).expect("解析");
        let plaintext = decrypt_v1(&counting_key(32), &envelope).expect("解密");
        assert_eq!(
            plaintext.expose(),
            hex("e588b7e696b0e4bba4e7898c20726566726573685f746f6b656e20e29c932000207461696c"),
            "字节序列取自 Bun 侧 Buffer.from(plaintext,'utf8').toString('hex')"
        );
        assert_eq!(plaintext.len(), 37);
    }

    /// 含 4 字节 UTF-8（emoji、ZWJ 序列、星光平面字符）的明文逐字节相等。
    ///
    /// 断言对象是**字节序列**而不是 Rust 字符串字面量：ZWJ（U+200D）在源码里不可见，写成
    /// 字面量的话"这个测试到底在测哪串字节"就只能靠猜。十六进制取自 Bun 侧
    /// `Buffer.from(plaintext,'utf8').toString('hex')`。
    #[test]
    fn upstream_plaintext_with_four_byte_utf8_survives_byte_for_byte() {
        let envelope = EnvelopeV1::parse(UPSTREAM_AES256_EMOJI).expect("解析");
        let plaintext = decrypt_v1(&counting_key(32), &envelope).expect("解密");

        let expected =
            hex("e5af86e992a5f09f9491207265667265736820f09f91a9e2808df09f9a8020f09d849e20656e64");
        assert_eq!(plaintext.expose(), expected);
        assert_eq!(plaintext.len(), 39);
        // 密文 = 明文 + 16 字节 tag，与 Bun 侧实测的 55 一致。
        assert_eq!(envelope.ciphertext().len(), 39 + TAG_BYTES);
        // 正向对照：解出来的确实是合法 UTF-8，且那三个 4 字节码点都在。
        let text = core::str::from_utf8(plaintext.expose()).expect("合法 UTF-8");
        assert!(text.contains('\u{1F511}'), "U+1F511 丢了");
        assert!(text.contains('\u{1D11E}'), "U+1D11E 丢了");
        assert!(text.contains('\u{200D}'), "ZWJ 丢了");
    }

    /// 负向对照三连：错密钥、改密文、改 IV，都必须拒绝。
    ///
    /// 没有这一组，上面那条"解得开"在"`decrypt_v1` 恒返回明文"的世界里同样通过。反过来，
    /// 只有这一组而没有"解得开"，则在"`decrypt_v1` 恒返回 `Err`"的世界里同样全绿 ——
    /// 两半必须都在。
    #[test]
    fn v1_rejects_wrong_key_and_tampering() {
        let envelope = EnvelopeV1::parse(UPSTREAM_AES256_ASCII).expect("解析");

        // 错密钥：与正确密钥只差最后一个字节。
        let mut wrong = (0u8..32).collect::<Vec<u8>>();
        wrong[31] ^= 0x01;
        let wrong_key = WrappingKey::from_bytes(wrong).expect("32 字节");
        assert_eq!(
            decrypt_v1(&wrong_key, &envelope).unwrap_err(),
            VaultError::Decrypt
        );

        // 改密文一个 bit。
        let mut ciphertext = envelope.ciphertext().to_vec();
        ciphertext[0] ^= 0x01;
        let tampered = EnvelopeV1::parse(&rebuild_v1(envelope.iv(), &ciphertext)).expect("解析");
        assert_eq!(
            decrypt_v1(&counting_key(32), &tampered).unwrap_err(),
            VaultError::Decrypt
        );

        // 改 tag（密文最后一个字节）。
        let mut tag_flipped = envelope.ciphertext().to_vec();
        let last = tag_flipped.len() - 1;
        tag_flipped[last] ^= 0x80;
        let tampered = EnvelopeV1::parse(&rebuild_v1(envelope.iv(), &tag_flipped)).expect("解析");
        assert_eq!(
            decrypt_v1(&counting_key(32), &tampered).unwrap_err(),
            VaultError::Decrypt
        );

        // 改 IV 一个 bit。
        let mut iv = *envelope.iv().as_bytes();
        iv[0] ^= 0x01;
        let tampered = EnvelopeV1::parse(&rebuild_v1(Nonce::from_array(iv), envelope.ciphertext()))
            .expect("解析");
        assert_eq!(
            decrypt_v1(&counting_key(32), &tampered).unwrap_err(),
            VaultError::Decrypt
        );
    }

    /// 用上游的字段顺序重新拼一条 v1 列值。只在测试里用于造篡改样本。
    fn rebuild_v1(iv: Nonce, ciphertext: &[u8]) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;
        format!(
            "{{\"version\":1,\"iv\":\"{}\",\"ciphertext\":\"{}\"}}",
            BASE64.encode(iv.as_bytes()),
            BASE64.encode(ciphertext)
        )
    }

    /// 用错档位的密钥长度去解，必须是认证失败而不是"当成另一档试试看"。
    #[test]
    fn v1_does_not_silently_fall_back_to_another_key_size() {
        let envelope = EnvelopeV1::parse(UPSTREAM_AES256_ASCII).expect("解析");
        // 这条信封是 256 位密钥封的；拿 128 / 192 位密钥来解必须失败。
        for length in [16usize, 24] {
            assert_eq!(
                decrypt_v1(&counting_key(length), &envelope).unwrap_err(),
                VaultError::Decrypt,
                "{length} 字节密钥不该解开一条 256 位的信封"
            );
        }
        // 正向对照：正确档位确实解得开。
        assert!(decrypt_v1(&counting_key(32), &envelope).is_ok());
    }

    // ───────────────────────────── v2：AAD 绑定 ─────────────────────────────

    fn kek() -> WrappingKey {
        WrappingKey::from_bytes(vec![0x5Au8; 32]).expect("32 字节")
    }

    fn dek() -> DataKey {
        DataKey::from_bytes(vec![0xA5u8; DATA_KEY_BYTES]).expect("32 字节")
    }

    fn binding_for(tenant: &str, secret: &str, version: u32) -> RecordBinding {
        RecordBinding::new(
            TenantId::new(tenant),
            SecretId::new(secret),
            SecretKind::Model,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new("gateway-1")),
            KeyVersion::new(version),
        )
    }

    /// v2 round-trip：封得上、解得开、明文逐字节相同。
    ///
    /// 这是下面一整组"必须失败"的正向对照。
    #[test]
    fn v2_round_trips_under_the_matching_binding() {
        let binding = binding_for("tenant-1", "secret-1", 3);
        let plaintext = b"sk-live-model-key";

        let envelope = seal_v2(
            &kek(),
            &dek(),
            &binding,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            plaintext,
        )
        .expect("封装");

        assert_eq!(envelope.key_version(), KeyVersion::new(3));
        let recovered = open_v2(&kek(), &binding, &envelope).expect("解封");
        assert_eq!(recovered.expose(), plaintext);

        // 经过一次列值 round-trip 之后依然解得开 —— 序列化没丢东西。
        let reparsed = EnvelopeV2::parse(&envelope.to_column_value()).expect("解析");
        assert_eq!(
            open_v2(&kek(), &binding, &reparsed).expect("解封").expose(),
            plaintext
        );
    }

    /// 六元组任意一项对不上，解密必须失败。**这是 §6.4 那条 AAD 绑定的全部意义。**
    #[test]
    fn v2_refuses_every_single_field_of_the_binding_being_wrong() {
        let binding = binding_for("tenant-1", "secret-1", 3);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &binding,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"payload",
        )
        .expect("封装");

        // tenant / secret_id / kind / owner / consumer 各错一次，key_version 单独测
        // （它在密码学之前就被拦下，错误码不同）。
        let wrong_tenant = binding_for("tenant-2", "secret-1", 3);
        let wrong_secret = binding_for("tenant-1", "secret-2", 3);
        let wrong_kind = RecordBinding::new(
            TenantId::new("tenant-1"),
            SecretId::new("secret-1"),
            SecretKind::Mcp,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new("gateway-1")),
            KeyVersion::new(3),
        );
        let wrong_owner = RecordBinding::new(
            TenantId::new("tenant-1"),
            SecretId::new("secret-1"),
            SecretKind::Model,
            SecretPrincipal::Actor(ActorId::new("mallory")),
            SecretPrincipal::Service(ServiceId::new("gateway-1")),
            KeyVersion::new(3),
        );
        let wrong_consumer = RecordBinding::new(
            TenantId::new("tenant-1"),
            SecretId::new("secret-1"),
            SecretKind::Model,
            SecretPrincipal::Deployment,
            SecretPrincipal::Service(ServiceId::new("gateway-2")),
            KeyVersion::new(3),
        );

        for (label, wrong) in [
            ("tenant", wrong_tenant),
            ("secret_id", wrong_secret),
            ("kind", wrong_kind),
            ("owner", wrong_owner),
            ("consumer", wrong_consumer),
        ] {
            assert_eq!(
                open_v2(&kek(), &wrong, &envelope).unwrap_err(),
                VaultError::Decrypt,
                "{label} 对不上时必须拒绝"
            );
        }

        // 正向对照：正确 binding 依然解得开（否则上面五条在"open_v2 恒失败"的世界里全绿）。
        assert!(open_v2(&kek(), &binding, &envelope).is_ok());
    }

    /// 改信封里的 `key_version` 会被**密码学之前**那道检查拦下，错误码可分辨。
    #[test]
    fn v2_rejects_a_ciphertext_that_claims_a_different_key_version() {
        let binding = binding_for("tenant-1", "secret-1", 3);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &binding,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"payload",
        )
        .expect("封装");

        // 攻击者把行里的 key_version 改成一个已泄漏的旧版本。
        let forged = EnvelopeV2::parse(
            &envelope
                .to_column_value()
                .replace("\"key_version\":3", "\"key_version\":1"),
        )
        .expect("解析");

        assert_eq!(
            open_v2(&kek(), &binding, &forged).unwrap_err(),
            VaultError::KeyVersionMismatch,
            "必须在做任何密码学运算之前拒绝"
        );

        // 调用方"配合"地把 binding 也改成 1 —— 那就轮到 AAD 拦它，错误码变成认证失败。
        let downgraded = binding.with_key_version(KeyVersion::new(1));
        assert_eq!(
            open_v2(&kek(), &downgraded, &forged).unwrap_err(),
            VaultError::Decrypt,
            "key_version 进了 AAD，所以改版本号也解不开"
        );
    }

    /// 换 KEK 版本之后旧密文解不开 —— 这是**设计意图**，见 [`super::super::binding`] 模块文档。
    #[test]
    fn v2_ciphertext_does_not_survive_a_key_version_bump() {
        let old = binding_for("tenant-1", "secret-1", 1);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &old,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"payload",
        )
        .expect("封装");

        let bumped = old.with_key_version(KeyVersion::new(2));
        assert_eq!(
            open_v2(&kek(), &bumped, &envelope).unwrap_err(),
            VaultError::KeyVersionMismatch
        );
        // 正向对照：旧 binding 仍然解得开，所以密文本身没坏。
        assert!(open_v2(&kek(), &old, &envelope).is_ok());
    }

    /// 密文不能在两条记录之间搬家 —— v1 能，v2 不能。**这是 v2 存在的理由本身。**
    #[test]
    fn v2_ciphertext_cannot_be_relocated_but_v1_can() {
        // v2：把 secret-1 的密文整段搬到 secret-2 的行里。
        let source = binding_for("tenant-1", "secret-1", 1);
        let target = binding_for("tenant-1", "secret-2", 1);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &source,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"stolen",
        )
        .expect("封装");
        assert_eq!(
            open_v2(&kek(), &target, &envelope).unwrap_err(),
            VaultError::Decrypt,
            "搬家必须失败"
        );

        // v1 的对照：同一把 KEY_ENCRYPTION_KEY 下，密文与"它属于哪一行"毫无关系 ——
        // 上游那条真信封在任何记录身份下都解得开，因为根本没有记录身份这个概念。
        let legacy = EnvelopeV1::parse(UPSTREAM_AES256_ASCII).expect("解析");
        assert!(
            decrypt_v1(&counting_key(32), &legacy).is_ok(),
            "v1 没有 AAD，所以它无从拒绝搬家 —— 这正是 v2 要关掉的洞"
        );
    }

    /// record 与 DEK 两处密文不能互换位置（域分隔的运行期验证）。
    #[test]
    fn wrapped_dek_and_record_ciphertext_are_not_interchangeable() {
        let binding = binding_for("tenant-1", "secret-1", 1);
        let dek_nonce = Nonce::from_array([1u8; NONCE_BYTES]);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &binding,
            dek_nonce,
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"payload",
        )
        .expect("封装");

        // 正向对照：用正确的 AAD 域，包装的 DEK 解得开。
        assert!(unwrap_data_key(&kek(), &binding, dek_nonce, envelope.wrapped_dek()).is_ok());

        // 拿 record 的 AAD 去解 DEK 包装 —— 域分隔让它必然失败。
        assert_eq!(
            aes_gcm_decrypt(
                kek().material(),
                dek_nonce,
                &binding.record_aad(),
                envelope.wrapped_dek(),
            )
            .unwrap_err(),
            VaultError::Decrypt
        );
    }

    /// 空明文在 v2 下同样可用（上游允许加密空字符串，迁移过来的值可能就是空的）。
    #[test]
    fn v2_handles_empty_plaintext() {
        let binding = binding_for("tenant-1", "secret-1", 1);
        let envelope = seal_v2(
            &kek(),
            &dek(),
            &binding,
            Nonce::from_array([1u8; NONCE_BYTES]),
            Nonce::from_array([2u8; NONCE_BYTES]),
            b"",
        )
        .expect("封装");
        assert_eq!(envelope.ciphertext().len(), TAG_BYTES);
        let recovered = open_v2(&kek(), &binding, &envelope).expect("解封");
        assert!(recovered.is_empty());
    }
}

#[cfg(test)]
mod whole_pg_capture_tests {
    use super::*;
    #[test]
    fn detached_capture_preserves_legacy_aes256_output_and_authentication() {
        let key = SecretBytes::new(vec![11; 32]);
        let nonce = [13u8; 12];
        let aad = b"capture-bound-headers";
        let expected = aes_gcm_encrypt(
            key.expose(),
            Nonce::from_array(nonce),
            aad,
            b"capture-material",
        )
        .unwrap();
        let mut buffer = b"capture-material".to_vec();
        let tag = whole_pg_seal_in_place(&key, &nonce, aad, &mut buffer).unwrap();
        assert_eq!(buffer.as_slice(), &expected[..expected.len() - 16]);
        assert_eq!(tag.as_slice(), &expected[expected.len() - 16..]);
        whole_pg_open_in_place(&key, &nonce, aad, &tag, &mut buffer).unwrap();
        assert_eq!(buffer, b"capture-material");
    }
}
