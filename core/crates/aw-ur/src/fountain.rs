//! 喷泉码（多段 UR，BCR-2024-001）。分片组合的选择算法必须与参考实现逐位一致，
//! 才能和其他钱包互相扫码；这部分用 bc-ur 的测试向量逐项校验。
//!
//! 解码端输入不可信：分片数、消息长度、待处理的混合分片数都有上限。

use crate::cbor::{Reader, Writer};
use crate::sampler::RandomSampler;
use crate::xoshiro::Xoshiro256;
use crate::{crc32, UrError, MAX_MESSAGE_LEN, MAX_SEQ_LEN};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Indexes = BTreeSet<usize>;

/// 与参考实现相同：从 1 个分片开始逐个增加，直到分片长度不超过 max。
/// 参考实现在找不到时断言失败；这里退化为 max（编码端参数不影响互通）。
pub fn nominal_fragment_len(message_len: usize, min_len: usize, max_len: usize) -> usize {
    let max_count = message_len / min_len.max(1);
    (1..=max_count)
        .map(|count| message_len.div_ceil(count))
        .find(|&len| len <= max_len)
        .unwrap_or_else(|| max_len.min(message_len).max(1))
}

/// 切分消息，最后一片补零到 fragment_len。
pub fn partition(message: &[u8], fragment_len: usize) -> Vec<Vec<u8>> {
    message
        .chunks(fragment_len.max(1))
        .map(|c| {
            let mut v = c.to_vec();
            v.resize(fragment_len, 0);
            v
        })
        .collect()
}

pub(crate) fn choose_degree(seq_len: usize, rng: &mut Xoshiro256) -> usize {
    let probs: Vec<f64> = (1..=seq_len).map(|i| 1.0 / (i as f64)).collect();
    RandomSampler::new(&probs).map_or(1, |s| s.next(rng) + 1)
}

pub(crate) fn shuffled(mut remaining: Vec<usize>, rng: &mut Xoshiro256) -> Vec<usize> {
    let mut out = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let high = (remaining.len() - 1) as u64;
        let idx = usize::try_from(rng.next_int(0, high)).unwrap_or(0);
        out.push(remaining.remove(idx.min(remaining.len() - 1)));
    }
    out
}

/// 第 seq_num 段包含哪些分片的异或。前 seq_len 段是各分片原样；之后由伪随机决定。
pub fn choose_fragments(seq_num: u32, seq_len: usize, checksum: u32) -> Indexes {
    let n = seq_num as usize;
    if n >= 1 && n <= seq_len {
        return [n - 1].into_iter().collect();
    }
    let seed = [seq_num.to_be_bytes(), checksum.to_be_bytes()].concat();
    let mut rng = Xoshiro256::from_seed_bytes(&seed);
    let degree = choose_degree(seq_len, &mut rng);
    shuffled((0..seq_len).collect(), &mut rng)
        .into_iter()
        .take(degree)
        .collect()
}

fn xor_into(target: &mut [u8], other: &[u8]) {
    target.iter_mut().zip(other).for_each(|(a, b)| *a ^= b);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub seq_num: u32,
    pub seq_len: usize,
    pub message_len: usize,
    pub checksum: u32,
    pub data: Vec<u8>,
}

impl Part {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(5)
            .uint(u64::from(self.seq_num))
            .uint(self.seq_len as u64)
            .uint(self.message_len as u64)
            .uint(u64::from(self.checksum))
            .bytes(&self.data);
        w.into_bytes()
    }

    /// 严格解析，并做一致性检查（参考编码器产生的分片一定满足这些条件）。
    pub fn from_cbor(b: &[u8]) -> Result<Part, UrError> {
        let mut r = Reader::new(b);
        if r.array()? != 5 {
            return Err(UrError::Cbor);
        }
        let seq_num = r.u32()?;
        let seq_len = usize::try_from(r.uint()?).map_err(|_| UrError::TooLarge)?;
        let message_len = usize::try_from(r.uint()?).map_err(|_| UrError::TooLarge)?;
        let checksum = r.u32()?;
        let data = r.bytes()?.to_vec();
        r.finish()?;
        if seq_len == 0
            || seq_len > MAX_SEQ_LEN
            || message_len == 0
            || message_len > MAX_MESSAGE_LEN
        {
            return Err(UrError::TooLarge);
        }
        let frag = data.len();
        if seq_num == 0
            || frag == 0
            || seq_len.saturating_mul(frag) < message_len
            || (seq_len - 1).saturating_mul(frag) >= message_len
        {
            return Err(UrError::Inconsistent);
        }
        Ok(Part {
            seq_num,
            seq_len,
            message_len,
            checksum,
            data,
        })
    }

    #[cfg(test)]
    pub fn description(&self) -> String {
        let hex: String = self.data.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "seqNum:{}, seqLen:{}, messageLen:{}, checksum:{}, data:{}",
            self.seq_num, self.seq_len, self.message_len, self.checksum, hex
        )
    }
}

pub struct FountainEncoder {
    fragments: Vec<Vec<u8>>,
    message_len: usize,
    checksum: u32,
    fragment_len: usize,
    seq_num: u32,
}

impl FountainEncoder {
    pub fn new(
        message: &[u8],
        max_fragment_len: usize,
        first_seq_num: u32,
        min_fragment_len: usize,
    ) -> Result<Self, UrError> {
        if message.is_empty()
            || message.len() > MAX_MESSAGE_LEN
            || min_fragment_len == 0
            || max_fragment_len < min_fragment_len
        {
            return Err(UrError::TooLarge);
        }
        let fragment_len = nominal_fragment_len(message.len(), min_fragment_len, max_fragment_len);
        let fragments = partition(message, fragment_len);
        if fragments.len() > MAX_SEQ_LEN {
            return Err(UrError::TooLarge);
        }
        Ok(Self {
            fragments,
            message_len: message.len(),
            checksum: crc32::checksum(message),
            fragment_len,
            seq_num: first_seq_num,
        })
    }

    pub fn seq_len(&self) -> usize {
        self.fragments.len()
    }

    pub fn is_single_part(&self) -> bool {
        self.seq_len() == 1
    }

    /// 已经至少输出过一轮全部原始分片。
    pub fn is_complete(&self) -> bool {
        self.seq_num as usize >= self.seq_len()
    }

    pub fn next_part(&mut self) -> Part {
        self.seq_num = self.seq_num.wrapping_add(1);
        let indexes = choose_fragments(self.seq_num, self.seq_len(), self.checksum);
        let mut data = vec![0u8; self.fragment_len];
        for i in indexes {
            if let Some(f) = self.fragments.get(i) {
                xor_into(&mut data, f);
            }
        }
        Part {
            seq_num: self.seq_num,
            seq_len: self.seq_len(),
            message_len: self.message_len,
            checksum: self.checksum,
            data,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Expected {
    seq_len: usize,
    message_len: usize,
    checksum: u32,
    fragment_len: usize,
}

#[derive(Default)]
pub struct FountainDecoder {
    expected: Option<Expected>,
    simple: BTreeMap<usize, Vec<u8>>,
    mixed: BTreeMap<Indexes, Vec<u8>>,
    queue: VecDeque<(Indexes, Vec<u8>)>,
    result: Option<Result<Vec<u8>, UrError>>,
}

impl FountainDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_complete(&self) -> bool {
        self.result.is_some()
    }

    pub fn result(&self) -> Option<&Result<Vec<u8>, UrError>> {
        self.result.as_ref()
    }

    /// 已恢复的原始分片数 / 总分片数（用于界面进度条）。
    pub fn progress(&self) -> (usize, usize) {
        (self.simple.len(), self.expected.map_or(0, |e| e.seq_len))
    }

    /// 收下一段。与已收分片不一致时返回 `Err(Inconsistent)`，调用方应提示"换了另一组二维码"。
    pub fn receive(&mut self, part: &Part) -> Result<(), UrError> {
        if self.result.is_some() {
            return Ok(());
        }
        let this = Expected {
            seq_len: part.seq_len,
            message_len: part.message_len,
            checksum: part.checksum,
            fragment_len: part.data.len(),
        };
        match self.expected {
            None => self.expected = Some(this),
            Some(e) if e != this => return Err(UrError::Inconsistent),
            Some(_) => {}
        }
        let indexes = choose_fragments(part.seq_num, part.seq_len, part.checksum);
        self.queue.push_back((indexes, part.data.clone()));
        while self.result.is_none() {
            let Some((idx, data)) = self.queue.pop_front() else {
                break;
            };
            if idx.len() == 1 {
                self.process_simple(idx, data);
            } else {
                self.process_mixed(idx, data);
            }
        }
        Ok(())
    }

    fn process_simple(&mut self, idx: Indexes, data: Vec<u8>) {
        let Some(&i) = idx.iter().next() else { return };
        if self.simple.contains_key(&i) {
            return;
        }
        self.simple.insert(i, data.clone());
        let Some(e) = self.expected else { return };
        if self.simple.len() == e.seq_len {
            let mut message: Vec<u8> = self.simple.values().flatten().copied().collect();
            message.truncate(e.message_len);
            self.result = Some(if crc32::checksum(&message) == e.checksum {
                Ok(message)
            } else {
                Err(UrError::Checksum)
            });
        } else {
            self.reduce_mixed_by(&idx, &data);
        }
    }

    fn reduce(a: (Indexes, Vec<u8>), b_idx: &Indexes, b_data: &[u8]) -> (Indexes, Vec<u8>) {
        let (a_idx, mut a_data) = a;
        if b_idx != &a_idx && b_idx.is_subset(&a_idx) {
            xor_into(&mut a_data, b_data);
            (a_idx.difference(b_idx).copied().collect(), a_data)
        } else {
            (a_idx, a_data)
        }
    }

    fn reduce_mixed_by(&mut self, idx: &Indexes, data: &[u8]) {
        let old = std::mem::take(&mut self.mixed);
        for (k, v) in old {
            let (k2, v2) = Self::reduce((k, v), idx, data);
            if k2.len() == 1 {
                self.queue.push_back((k2, v2));
            } else {
                self.mixed.entry(k2).or_insert(v2);
            }
        }
    }

    fn process_mixed(&mut self, idx: Indexes, data: Vec<u8>) {
        if self.mixed.contains_key(&idx) {
            return;
        }
        let mut p = (idx, data);
        for (&i, d) in &self.simple {
            p = Self::reduce(p, &[i].into_iter().collect(), d);
        }
        for (k, v) in &self.mixed {
            p = Self::reduce(p, k, v);
        }
        if p.0.len() == 1 {
            self.queue.push_back(p);
            return;
        }
        self.reduce_mixed_by(&p.0, &p.1);
        // 恶意输入可能不断送来新的混合分片：设上限，诚实编码器远达不到
        let cap = self.expected.map_or(0, |e| e.seq_len.saturating_mul(4));
        if self.mixed.len() < cap {
            self.mixed.entry(p.0).or_insert(p.1);
        }
    }
}

/// 测试辅助：从 third_party/bc-ur/test/test.cpp 中解析参考期望值（避免手抄）。
#[cfg(test)]
pub(crate) mod refvec {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    const TEST_CPP: &str = include_str!("../../../../third_party/bc-ur/test/test.cpp");

    /// 取出 `static void <name>() {` 到下一个函数之前的文本。
    pub fn section(name: &str) -> String {
        let head = format!("static void {name}() {{");
        let start = TEST_CPP
            .find(&head)
            .unwrap_or_else(|| panic!("找不到 {name}"));
        let rest = &TEST_CPP[start + head.len()..];
        let end = rest
            .find("\nstatic ")
            .or_else(|| rest.find("\nint main"))
            .unwrap();
        rest[..end].to_string()
    }

    /// `marker` 之后、匹配的 `}` 之前出现的全部整数（忽略嵌套括号）。
    pub fn ints_after(text: &str, marker: &str) -> Vec<u64> {
        let start = text
            .find(marker)
            .unwrap_or_else(|| panic!("找不到 {marker}"))
            + marker.len();
        let mut depth = 1;
        let mut end = start;
        for (i, c) in text[start..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        text[start..end]
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap())
            .collect()
    }

    /// `marker` 之后的嵌套整数组：`{ {1,2}, {3} }` → [[1,2],[3]]
    pub fn int_groups_after(text: &str, marker: &str) -> Vec<Vec<u64>> {
        let start = text.find(marker).unwrap() + marker.len();
        let body = &text[start..start + text[start..].find("};").unwrap()];
        body.split('{')
            .skip(1)
            .map(|g| {
                g[..g.find('}').unwrap()]
                    .split(|c: char| !c.is_ascii_digit())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().unwrap())
                    .collect()
            })
            .collect()
    }

    /// `marker` 之后到 `;` 之前的所有字符串字面量（按顺序）。
    pub fn strings_after(text: &str, marker: &str) -> Vec<String> {
        let start = text.find(marker).unwrap() + marker.len();
        let body = &text[start..start + text[start..].find(';').unwrap()];
        body.split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    /// 相邻字符串字面量拼接（C++ 中 "a" "b" 等于 "ab"）。
    pub fn joined_strings_after(text: &str, marker: &str) -> String {
        strings_after(text, marker).concat()
    }

    pub fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// test-utils.cpp: make_message(len, seed) = Xoshiro256(seed).next_data(len)
    pub fn make_message(len: usize, seed: &str) -> Vec<u8> {
        crate::xoshiro::Xoshiro256::from_seed_bytes(seed.as_bytes()).next_data(len)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::refvec::*;
    use super::*;

    #[test]
    fn reference_find_fragment_length() {
        assert_eq!(nominal_fragment_len(12345, 1005, 1955), 1764);
        assert_eq!(nominal_fragment_len(12345, 1005, 30000), 12345);
    }

    #[test]
    fn reference_partition_and_join() {
        let msg = make_message(1024, "Wolf");
        let len = nominal_fragment_len(msg.len(), 10, 100);
        let frags: Vec<String> = partition(&msg, len).iter().map(|f| to_hex(f)).collect();
        let want = strings_after(
            &section("test_partition_and_join"),
            "expected_fragments = {",
        );
        assert_eq!(want.len(), 11);
        assert_eq!(frags, want);
        let mut joined: Vec<u8> = partition(&msg, len).concat();
        joined.truncate(msg.len());
        assert_eq!(joined, msg);
    }

    #[test]
    fn reference_choose_degree() {
        let msg = make_message(1024, "Wolf");
        let n = partition(&msg, nominal_fragment_len(msg.len(), 10, 100)).len();
        let got: Vec<u64> = (1..=200)
            .map(|nonce| {
                let mut rng = Xoshiro256::from_seed_bytes(format!("Wolf-{nonce}").as_bytes());
                choose_degree(n, &mut rng) as u64
            })
            .collect();
        assert_eq!(
            got,
            ints_after(&section("test_choose_degree"), "expected_degrees = {")
        );
    }

    #[test]
    fn reference_shuffle() {
        let mut rng = Xoshiro256::from_seed_bytes(b"Wolf");
        let got: Vec<Vec<u64>> = (0..10)
            .map(|_| {
                shuffled((1..=10).collect(), &mut rng)
                    .into_iter()
                    .map(|v| v as u64)
                    .collect()
            })
            .collect();
        assert_eq!(
            got,
            int_groups_after(&section("test_shuffle"), "expectedResult = {")
        );
    }

    #[test]
    fn reference_choose_fragments() {
        let msg = make_message(1024, "Wolf");
        let checksum = crate::crc32::checksum(&msg);
        let n = partition(&msg, nominal_fragment_len(msg.len(), 10, 100)).len();
        let got: Vec<Vec<u64>> = (1..=30u32)
            .map(|s| {
                choose_fragments(s, n, checksum)
                    .into_iter()
                    .map(|v| v as u64)
                    .collect()
            })
            .collect();
        assert_eq!(
            got,
            int_groups_after(
                &section("test_choose_fragments"),
                "expected_fragment_indexes = {"
            )
        );
    }

    #[test]
    fn reference_xor() {
        let mut rng = Xoshiro256::from_seed_bytes(b"Wolf");
        let d1 = rng.next_data(10);
        let d2 = rng.next_data(10);
        assert_eq!(to_hex(&d1), "916ec65cf77cadf55cd7");
        assert_eq!(to_hex(&d2), "f9cda1a1030026ddd42e");
        let mut d3 = d1.clone();
        xor_into(&mut d3, &d2);
        assert_eq!(to_hex(&d3), "68a367fdf47c8b2888f9");
        xor_into(&mut d3, &d1);
        assert_eq!(d3, d2);
    }

    #[test]
    fn reference_encoder_parts_and_cbor() {
        let msg = make_message(256, "Wolf");
        let mut enc = FountainEncoder::new(&msg, 30, 0, 10).unwrap();
        let parts: Vec<Part> = (0..20).map(|_| enc.next_part()).collect();
        let desc: Vec<String> = parts.iter().map(Part::description).collect();
        assert_eq!(
            desc,
            strings_after(&section("test_fountain_encoder"), "expected_parts = {")
        );
        let cbor: Vec<String> = parts.iter().map(|p| to_hex(&p.to_cbor())).collect();
        assert_eq!(
            cbor,
            strings_after(&section("test_fountain_encoder_cbor"), "expected_parts = {")
        );
        for p in &parts {
            assert_eq!(&Part::from_cbor(&p.to_cbor()).unwrap(), p);
        }
    }

    #[test]
    fn reference_encoder_is_complete() {
        let msg = make_message(256, "Wolf");
        let mut enc = FountainEncoder::new(&msg, 30, 0, 10).unwrap();
        let mut count = 0;
        while !enc.is_complete() {
            enc.next_part();
            count += 1;
        }
        assert_eq!(count, enc.seq_len());
    }

    /// bc-ur test.cpp: test_fountain_decoder（32767 字节，分片上限 1000，从第 100 段开始）
    #[test]
    fn reference_decoder_roundtrip() {
        let msg = make_message(32767, "Wolf");
        let mut enc = FountainEncoder::new(&msg, 1000, 100, 10).unwrap();
        let mut dec = FountainDecoder::new();
        let mut n = 0;
        while !dec.is_complete() {
            dec.receive(&enc.next_part()).unwrap();
            n += 1;
            assert!(n < 1000, "解码不收敛");
        }
        assert_eq!(dec.result().unwrap().as_ref().unwrap(), &msg);
    }

    #[test]
    fn decoder_recovers_when_first_parts_are_lost() {
        let msg = make_message(5000, "Lost");
        let mut enc = FountainEncoder::new(&msg, 200, 0, 10).unwrap();
        let mut dec = FountainDecoder::new();
        let mut n = 0;
        while !dec.is_complete() {
            let p = enc.next_part();
            n += 1;
            // 模拟摄像头漏掉三分之二的帧
            if n % 3 == 0 {
                dec.receive(&p).unwrap();
            }
            assert!(n < 5000);
        }
        assert_eq!(dec.result().unwrap().as_ref().unwrap(), &msg);
    }

    #[test]
    fn decoder_rejects_mixed_streams_and_bad_parts() {
        let a = make_message(500, "A");
        let b = make_message(600, "B");
        let mut ea = FountainEncoder::new(&a, 100, 0, 10).unwrap();
        let mut eb = FountainEncoder::new(&b, 100, 0, 10).unwrap();
        let mut dec = FountainDecoder::new();
        dec.receive(&ea.next_part()).unwrap();
        assert_eq!(dec.receive(&eb.next_part()), Err(UrError::Inconsistent));
        // 伪造：分片数与长度矛盾
        let mut p = ea.next_part();
        p.seq_len = 1;
        assert!(Part::from_cbor(&p.to_cbor()).is_err());
        // 伪造：超大分片数
        let mut p = ea.next_part();
        p.seq_len = MAX_SEQ_LEN + 1;
        assert_eq!(Part::from_cbor(&p.to_cbor()), Err(UrError::TooLarge));
    }

    #[test]
    fn decoder_detects_corrupted_fragment() {
        let msg = make_message(300, "C");
        let mut enc = FountainEncoder::new(&msg, 100, 0, 10).unwrap();
        let mut dec = FountainDecoder::new();
        for _ in 0..enc.seq_len() {
            let mut p = enc.next_part();
            if p.seq_num == 2 {
                p.data[0] ^= 1;
            }
            dec.receive(&p).unwrap();
        }
        assert_eq!(dec.result(), Some(&Err(UrError::Checksum)));
    }

    #[test]
    fn reference_part_cbor_roundtrip() {
        let p = Part {
            seq_num: 12,
            seq_len: 8,
            message_len: 100,
            checksum: 0x1234_5678,
            data: vec![1, 5, 3, 3, 5],
        };
        // 参考测试只要求往返一致；这个分片本身不满足一致性约束（8×5 < 100），我们的解析会拒绝
        assert_eq!(Part::from_cbor(&p.to_cbor()), Err(UrError::Inconsistent));
        let ok = Part {
            seq_num: 12,
            seq_len: 20,
            message_len: 100,
            checksum: 0x1234_5678,
            data: vec![1, 5, 3, 3, 5],
        };
        assert_eq!(Part::from_cbor(&ok.to_cbor()).unwrap(), ok);
    }
}
