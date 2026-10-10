//! Walker 别名法随机采样（Vose 变体），逐步对应 bc-ur random-sampler.cpp，
//! 浮点运算顺序保持一致，以保证与其他实现选出相同的分片组合。
#![allow(clippy::indexing_slicing)] // 所有下标都由构造保证小于 n

use crate::xoshiro::Xoshiro256;

pub(crate) struct RandomSampler {
    probs: Vec<f64>,
    aliases: Vec<usize>,
}

impl RandomSampler {
    /// 概率必须非负且总和大于 0；否则返回 None。
    pub fn new(input: &[f64]) -> Option<Self> {
        let n = input.len();
        if n == 0 || input.iter().any(|p| p.is_nan() || *p < 0.0) {
            return None;
        }
        let sum = input.iter().fold(0.0f64, |a, b| a + b);
        if sum.is_nan() || sum <= 0.0 {
            return None;
        }
        let mut p: Vec<f64> = input.iter().map(|d| d * (n as f64) / sum).collect();
        let mut small = Vec::with_capacity(n);
        let mut large = Vec::with_capacity(n);
        for i in (0..n).rev() {
            if p[i] < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }
        let mut probs = vec![0.0f64; n];
        let mut aliases = vec![0usize; n];
        while !small.is_empty() && !large.is_empty() {
            let (Some(a), Some(g)) = (small.pop(), large.pop()) else {
                break;
            };
            probs[a] = p[a];
            aliases[a] = g;
            p[g] += p[a] - 1.0;
            if p[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }
        while let Some(g) = large.pop() {
            probs[g] = 1.0;
        }
        while let Some(a) = small.pop() {
            probs[a] = 1.0;
        }
        Some(Self { probs, aliases })
    }

    pub fn next(&self, rng: &mut Xoshiro256) -> usize {
        let r1 = rng.next_double();
        let r2 = rng.next_double();
        let n = self.probs.len();
        // r1 == 1.0 时参考实现越界；截到 n-1
        let i = (((n as f64) * r1) as usize).min(n - 1);
        if r2 < self.probs[i] {
            i
        } else {
            self.aliases[i]
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::fountain::refvec;

    /// bc-ur test.cpp: test_random_sampler（500 个样本）
    #[test]
    fn reference_sampler() {
        let sampler = RandomSampler::new(&[1.0, 2.0, 4.0, 8.0]).unwrap();
        let mut rng = Xoshiro256::from_seed_bytes(b"Wolf");
        let got: Vec<u64> = (0..500).map(|_| sampler.next(&mut rng) as u64).collect();
        let want = refvec::ints_after(
            &refvec::section("test_random_sampler"),
            "expected_samples = {",
        );
        assert_eq!(want.len(), 500);
        assert_eq!(got, want);
    }

    #[test]
    fn rejects_bad_probabilities() {
        assert!(RandomSampler::new(&[]).is_none());
        assert!(RandomSampler::new(&[0.0, 0.0]).is_none());
        assert!(RandomSampler::new(&[1.0, -1.0]).is_none());
        assert!(RandomSampler::new(&[f64::NAN]).is_none());
    }
}
