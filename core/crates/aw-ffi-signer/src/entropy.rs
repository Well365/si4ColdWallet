//! 助记词的熵（威胁 T1：弱随机数，如 Milk Sad / Trust Wallet 2023、Profanity、Libbitcoin bx）。
//!
//! 两种模式：
//! - **混合（默认）**：熵 = SHA-256(标签 ‖ 系统随机数 32 字节 ‖ 骰子次数 ‖ 骰子点数)。系统随机数先做
//!   健康检查；只要骰子足够多，即使系统随机数有缺陷（或被做了手脚），结果依然安全。
//! - **纯骰子（可独立验证）**：熵 = SHA-256(骰子点数字符串) 的前 16 / 32 字节（与 Coldcard 的做法相同）。
//!   完全不用设备随机数；用户可以在任何电脑上用 `shasum -a 256` 复算，确认助记词确实来自自己掷的骰子，
//!   见 `tools/testvectors/verify_dice.py`。
//!
//! 健康检查只能发现"坏掉"的随机数（全零、卡住、重复、明显的规律），不能证明随机——
//! 这正是建议加骰子的原因。

use aw_common::secret::SecretBytes;
use bitcoin::hashes::{sha256, Hash, HashEngine};

/// 骰子每次约 2.585 位熵：50 次 ≈ 129 位（12 词需 128 位），100 次 ≈ 258 位（24 词需 256 位）
pub const MIN_DICE_12: usize = 50;
pub const MIN_DICE_24: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// 系统随机数没有通过健康检查
    Health,
    /// 纯骰子模式下次数不够
    TooFewDice,
    /// 骰子点数只能是 1–6
    BadDice,
    /// 点数分布不像真实掷骰（某一面过多、长串相同、有周期）——可能是乱按或编造的
    PoorDice,
}

/// 系统随机数健康检查（参考 NIST SP 800-90B 的重复计数与比例测试，按 32 字节样本收紧）。
/// 对真正随机的 32 字节，下面任一条件成立的概率都小于 1e-8。
pub fn system_health(
    sys: &[u8; 32],
    previous_digest: Option<&[u8; 32]>,
) -> Result<(), EntropyError> {
    // 1. 不同字节值的个数：真随机时期望约 30 个，≤ 15 个的概率可以忽略
    let mut seen = [false; 256];
    for &b in sys {
        if let Some(s) = seen.get_mut(usize::from(b)) {
            *s = true;
        }
    }
    if seen.iter().filter(|&&s| s).count() <= 15 {
        return Err(EntropyError::Health);
    }
    // 2. 连续相同字节：出现 5 个以上（含）视为卡住
    let mut run = 1;
    for w in sys.windows(2) {
        run = if w.first() == w.get(1) { run + 1 } else { 1 };
        if run >= 5 {
            return Err(EntropyError::Health);
        }
    }
    // 3. 等差数列（如 00 01 02 …）：前 8 字节相邻差值全相同
    let diffs: Vec<u8> = sys
        .windows(2)
        .take(7)
        .map(|w| {
            w.get(1)
                .copied()
                .unwrap_or(0)
                .wrapping_sub(w.first().copied().unwrap_or(0))
        })
        .collect();
    if diffs.windows(2).all(|d| d.first() == d.get(1)) {
        return Err(EntropyError::Health);
    }
    // 4. 与本会话上一次的系统随机数相同（随机数源卡住）
    if previous_digest.is_some_and(|p| *p == digest(sys)) {
        return Err(EntropyError::Health);
    }
    Ok(())
}

/// 记录"上一次系统随机数"时只保存它的哈希，不保存原值
pub fn digest(sys: &[u8; 32]) -> [u8; 32] {
    let mut e = sha256::HashEngine::default();
    e.input(b"airgap-wallet/last-system-random/v1");
    e.input(sys);
    sha256::Hash::from_engine(e).to_byte_array()
}

fn check_dice(dice: &[u8]) -> Result<(), EntropyError> {
    if dice.iter().any(|c| !(b'1'..=b'6').contains(c)) {
        return Err(EntropyError::BadDice);
    }
    Ok(())
}

fn take(digest: [u8; 32], bytes: usize) -> SecretBytes<32> {
    let mut out = SecretBytes::<32>::zeroed();
    out.expose_mut()
        .iter_mut()
        .zip(digest.iter())
        .take(bytes)
        .for_each(|(o, d)| *o = *d);
    out
}

/// 混合模式：系统随机数 + 可选骰子（骰子可以为空）
pub fn mixed(
    system: &[u8; 32],
    dice: &[u8],
    bytes: usize,
) -> Result<SecretBytes<32>, EntropyError> {
    check_dice(dice)?;
    let mut e = sha256::HashEngine::default();
    e.input(b"airgap-wallet/entropy/v1");
    e.input(system);
    e.input(&(dice.len() as u64).to_be_bytes());
    e.input(dice);
    Ok(take(sha256::Hash::from_engine(e).to_byte_array(), bytes))
}

/// 纯骰子模式下检查点数"像不像真掷的"（随机数审查 M1：同一个按钮按 100 次也能通过次数检查）。
/// 三项检查对真实骰子的误报概率都约在 1e-5 或更低：
/// - 卡方检验（5 个自由度）> 35.9（p ≈ 1e-6）：某几面明显过多或过少
/// - 连续 10 个以上相同点数
/// - 整串以 ≤ 12 为周期重复（如 123456123456…）
pub fn dice_quality(dice: &[u8]) -> Result<(), EntropyError> {
    let n = dice.len();
    let mut counts = [0usize; 6];
    for &c in dice {
        if let Some(x) = counts.get_mut(usize::from(c.wrapping_sub(b'1'))) {
            *x += 1;
        }
    }
    // 卡方 = Σ(6c − n)² / (6n)；用整数比较：Σ(6c − n)² × 10 > 359 × 6n
    let sum: u128 = counts
        .iter()
        .map(|&c| {
            let d = (6 * c).abs_diff(n) as u128;
            d * d
        })
        .sum();
    if sum * 10 > 359 * 6 * n as u128 {
        return Err(EntropyError::PoorDice);
    }
    let mut run = 1;
    for w in dice.windows(2) {
        run = if w.first() == w.get(1) { run + 1 } else { 1 };
        if run >= 10 {
            return Err(EntropyError::PoorDice);
        }
    }
    for p in 1..=12usize.min(n.saturating_sub(1)) {
        if dice.iter().zip(dice.iter().skip(p)).all(|(a, b)| a == b) {
            return Err(EntropyError::PoorDice);
        }
    }
    Ok(())
}

/// 纯骰子模式：熵 = SHA-256(骰子点数字符串)，可在任何电脑上复算
pub fn dice_only(dice: &[u8], bytes: usize) -> Result<SecretBytes<32>, EntropyError> {
    check_dice(dice)?;
    let need = if bytes <= 16 {
        MIN_DICE_12
    } else {
        MIN_DICE_24
    };
    if dice.len() < need {
        return Err(EntropyError::TooFewDice);
    }
    dice_quality(dice)?;
    Ok(take(sha256::Hash::hash(dice).to_byte_array(), bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn good() -> [u8; 32] {
        sha256::Hash::hash(b"some good randomness").to_byte_array()
    }

    #[test]
    fn health_accepts_random_and_rejects_broken() {
        let g = good();
        assert_eq!(system_health(&g, None), Ok(()));
        // 全零、全相同、只有少数几种字节、长串重复、等差、与上次相同
        assert_eq!(system_health(&[0; 32], None), Err(EntropyError::Health));
        assert_eq!(system_health(&[0xab; 32], None), Err(EntropyError::Health));
        let mut few = [0u8; 32];
        for (i, b) in few.iter_mut().enumerate() {
            *b = (i % 15) as u8 * 17;
        }
        assert_eq!(system_health(&few, None), Err(EntropyError::Health));
        let mut run = g;
        run[10..15].copy_from_slice(&[7; 5]);
        assert_eq!(system_health(&run, None), Err(EntropyError::Health));
        let mut seq = [0u8; 32];
        for (i, b) in seq.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(11);
        }
        assert_eq!(system_health(&seq, None), Err(EntropyError::Health));
        assert_eq!(
            system_health(&g, Some(&digest(&g))),
            Err(EntropyError::Health)
        );
        assert_eq!(system_health(&g, Some(&digest(&[1; 32]))), Ok(()));
    }

    /// 一串"真实感"的骰子（Python random 固定种子 20261010 生成，只用作测试数据）
    pub(crate) const DICE_100: &[u8] = b"3261633433362244155334522333116113343614426455154252153355654526544131445632166514254645352524633213";
    pub(crate) const DICE_50: &[u8] = b"36311562263611226555616515224256255211145451122312";

    /// 纯骰子模式与 `shasum -a 256` 一致（期望值由 tools/testvectors/verify_dice.py 用 Python hashlib 算出）
    #[test]
    fn dice_only_matches_sha256_of_the_roll_string() {
        let e = dice_only(DICE_100, 32).unwrap();
        assert_eq!(
            aw_common::hex::encode(e.expose()),
            "a4126419d5b3c9f9aba14ce4f24043df19f774e43323be9fc876bd4a3a558658"
        );
        let e12 = dice_only(DICE_50, 16).unwrap();
        assert_eq!(
            aw_common::hex::encode(&e12.expose()[..16]),
            "e80ddcf1e800691dc181041b6504dffb"
        );
        assert_eq!(&e12.expose()[16..], &[0u8; 16]);
        assert_eq!(
            dice_only(&DICE_50[..49], 16).map(|_| ()),
            Err(EntropyError::TooFewDice)
        );
        assert_eq!(
            dice_only(&DICE_100[..99], 32).map(|_| ()),
            Err(EntropyError::TooFewDice)
        );
        assert_eq!(dice_only(b"7", 16).map(|_| ()), Err(EntropyError::BadDice));
        assert_eq!(
            mixed(&good(), b"0", 16).map(|_| ()),
            Err(EntropyError::BadDice)
        );
        // 混合模式：骰子不同 → 熵不同；骰子为空也可以
        let a = mixed(&good(), b"1", 32).unwrap();
        let b = mixed(&good(), b"2", 32).unwrap();
        assert_ne!(a.expose(), b.expose());
        assert!(mixed(&good(), b"", 32).is_ok());
    }

    /// 随机数审查 M1：乱按或编造的骰子被拒
    #[test]
    fn poor_dice_rejected() {
        let one: Vec<u8> = vec![b'1'; 100];
        let cyc: Vec<u8> = b"123456".iter().copied().cycle().take(100).collect();
        let cyc12: Vec<u8> = b"615243342516".iter().copied().cycle().take(100).collect();
        let mut run = DICE_100.to_vec();
        run[40..50].copy_from_slice(b"5555555555");
        let mut skew = DICE_100.to_vec();
        for c in skew.iter_mut().step_by(2) {
            *c = b'6';
        }
        for bad in [&one, &cyc, &cyc12, &run, &skew] {
            assert_eq!(dice_only(bad, 32).map(|_| ()), Err(EntropyError::PoorDice));
        }
        assert_eq!(dice_quality(DICE_100), Ok(()));
        assert_eq!(dice_quality(DICE_50), Ok(()));
    }
}
