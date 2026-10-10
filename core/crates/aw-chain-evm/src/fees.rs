//! 观察机的手续费档位（决策 D35）：从节点给的原始数据算出"慢 / 标准 / 快"三档。
//!
//! 节点不可信：这里只用检查算术，结果只用来构造交易；交易内容（含手续费）仍由签名机独立审查，
//! 单价、优先费、手续费占比异常都有告警，"总计最多扣除"一行给出最坏情况。

use crate::uint::U256;
use crate::EvmError;

/// eth_feeHistory 最多参考多少个区块
pub const MAX_HISTORY_BLOCKS: usize = 64;

/// 档位
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Standard,
    Fast,
}

impl Speed {
    pub const ALL: [Speed; 3] = [Speed::Slow, Speed::Standard, Speed::Fast];

    pub fn key(self) -> &'static str {
        match self {
            Self::Slow => "slow",
            Self::Standard => "standard",
            Self::Fast => "fast",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Slow => "慢",
            Self::Standard => "标准",
            Self::Fast => "快",
        }
    }

    /// EIP-1559 基础费放大倍数（分子, 分母）：基础费每个区块最多涨 12.5%，2 倍约可覆盖连续 6 个满区块
    fn base_multiplier(self) -> (u64, u64) {
        match self {
            Self::Slow => (5, 4),
            Self::Standard => (3, 2),
            Self::Fast => (2, 1),
        }
    }

    /// 旧式链 gas 单价倍数：慢档就是节点建议值，不往下压（低于节点最低价的交易不会被打包）
    fn legacy_multiplier(self) -> (u64, u64) {
        match self {
            Self::Slow => (1, 1),
            Self::Standard => (5, 4),
            Self::Fast => (3, 2),
        }
    }
}

/// 一档手续费（单位 wei / gas）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    pub speed: Speed,
    pub max_priority_fee: U256,
    pub max_fee: U256,
}

fn scale(v: U256, (num, den): (u64, u64)) -> Result<U256, EvmError> {
    v.checked_mul(U256::from_u64(num))
        .and_then(|x| x.checked_div_u64(den))
        .ok_or(EvmError::Overflow)
}

/// 中位数（偶数个时取较高的一个）；空列表为 None
fn median(mut v: Vec<U256>) -> Option<U256> {
    v.sort_unstable();
    v.get(v.len() / 2).copied()
}

fn tier(speed: Speed, base: U256, prio: U256) -> Result<Tier, EvmError> {
    let max_fee = base.checked_add(prio).ok_or(EvmError::Overflow)?;
    if max_fee.is_zero() {
        // 节点给的数据全为 0：这样的交易不会被打包，不如直接报错让用户换节点或自定义
        return Err(EvmError::Parse);
    }
    Ok(Tier {
        speed,
        max_priority_fee: prio,
        max_fee,
    })
}

/// EIP-1559 三档。`base_fee` 是下一区块的基础费；`rewards` 是 eth_feeHistory 的 reward
/// （每个区块 [p10, p50, p90] 三个百分位的优先费）；`suggested` 是 eth_maxPriorityFeePerGas。
/// - 慢：优先费 = p10 的中位数（不超过标准档；基础费与它都为 0 时取标准档），最高单价 = 基础费 × 5/4 + 优先费
/// - 标准：优先费 = max(p50 的中位数, 节点建议值)，最高单价 = 基础费 × 3/2 + 优先费
/// - 快：优先费 = max(p90 的中位数, 标准档优先费)，最高单价 = 基础费 × 2 + 优先费
///
/// 没有历史数据时三档的优先费都取节点建议值。
pub fn eip1559_tiers(
    base_fee: U256,
    rewards: &[[U256; 3]],
    suggested: U256,
) -> Result<[Tier; 3], EvmError> {
    if rewards.len() > MAX_HISTORY_BLOCKS {
        return Err(EvmError::TooLong);
    }
    let column = |k: usize| {
        median(rewards.iter().filter_map(|r| r.get(k).copied()).collect()).unwrap_or(suggested)
    };
    let standard = column(1).max(suggested);
    let fast = column(2).max(standard);
    let mut slow = column(0).min(standard);
    if base_fee.is_zero() && slow.is_zero() {
        slow = standard;
    }
    let base = |s: Speed| scale(base_fee, s.base_multiplier());
    Ok([
        tier(Speed::Slow, base(Speed::Slow)?, slow)?,
        tier(Speed::Standard, base(Speed::Standard)?, standard)?,
        tier(Speed::Fast, base(Speed::Fast)?, fast)?,
    ])
}

/// 旧式链（节点没有基础费）：三档 = eth_gasPrice × 1、5/4、3/2；优先费 = 最高单价（交易仍是 EIP-1559 格式）
pub fn legacy_tiers(gas_price: U256) -> Result<[Tier; 3], EvmError> {
    let t = |s: Speed| -> Result<Tier, EvmError> {
        let p = scale(gas_price, s.legacy_multiplier())?;
        tier(s, U256::ZERO, p)
    };
    Ok([t(Speed::Slow)?, t(Speed::Standard)?, t(Speed::Fast)?])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const GWEI: u64 = 1_000_000_000;

    fn g(x: u64) -> U256 {
        U256::from_u64(x * GWEI)
    }

    fn row(a: u64, b: u64, c: u64) -> [U256; 3] {
        [g(a), g(b), g(c)]
    }

    #[test]
    fn eip1559_tiers_follow_the_documented_rules() {
        let t = eip1559_tiers(g(10), &[row(1, 2, 3), row(1, 2, 5), row(2, 3, 4)], g(2)).unwrap();
        // p10 中位数 1、p50 中位数 2（不低于建议值 2）、p90 中位数 4
        assert_eq!(t[0].max_priority_fee, g(1));
        assert_eq!(t[0].max_fee, U256::from_u64(13_500_000_000)); // 10 × 5/4 + 1
        assert_eq!(t[1].max_priority_fee, g(2));
        assert_eq!(t[1].max_fee, g(17)); // 10 × 3/2 + 2
        assert_eq!(t[2].max_priority_fee, g(4));
        assert_eq!(t[2].max_fee, g(24)); // 10 × 2 + 4
        assert_eq!(t.map(|x| x.speed), Speed::ALL);
    }

    #[test]
    fn eip1559_edge_cases() {
        // 偶数个区块：中位数取较高的一个
        let t = eip1559_tiers(g(10), &[row(1, 1, 1), row(3, 3, 3)], U256::ZERO).unwrap();
        assert_eq!(t[1].max_priority_fee, g(3));
        // 节点建议值高于历史：标准档取建议值，快档不低于标准档，慢档不高于标准档
        let t = eip1559_tiers(g(10), &[row(1, 2, 3)], g(5)).unwrap();
        assert_eq!(
            [
                t[0].max_priority_fee,
                t[1].max_priority_fee,
                t[2].max_priority_fee
            ],
            [g(1), g(5), g(5)]
        );
        // 没有历史数据：三档优先费都取建议值
        let t = eip1559_tiers(g(10), &[], g(2)).unwrap();
        assert!(t.iter().all(|x| x.max_priority_fee == g(2)));
        // 基础费为 0（BNB 链）且慢档优先费为 0：慢档改用标准档
        let t = eip1559_tiers(U256::ZERO, &[row(0, 1, 2)], g(1)).unwrap();
        assert_eq!(t[0].max_fee, g(1));
        // 全为 0：报错而不是给出不会被打包的 0 单价
        assert_eq!(
            eip1559_tiers(U256::ZERO, &[row(0, 0, 0)], U256::ZERO),
            Err(EvmError::Parse)
        );
        // 溢出与过多的历史区块
        assert_eq!(eip1559_tiers(U256::MAX, &[], g(1)), Err(EvmError::Overflow));
        let many = vec![row(1, 1, 1); MAX_HISTORY_BLOCKS + 1];
        assert_eq!(eip1559_tiers(g(1), &many, g(1)), Err(EvmError::TooLong));
    }

    #[test]
    fn legacy_tiers_scale_the_node_price() {
        let t = legacy_tiers(g(4)).unwrap();
        assert_eq!(t.map(|x| x.max_fee), [g(4), g(5), g(6)]);
        assert!(t.iter().all(|x| x.max_priority_fee == x.max_fee));
        assert_eq!(legacy_tiers(U256::ZERO), Err(EvmError::Parse));
    }
}
