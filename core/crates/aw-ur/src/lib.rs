//! UR（Uniform Resources，BCR-2020-005）动画二维码编解码，自实现（决策 D5）。
//!
//! 规范：third_party/bc-research/papers/bcr-2020-005-ur.md、bcr-2020-012-bytewords.md、
//! bcr-2024-001-multipart-ur.md。行为对照：third_party/bc-ur（C++ 参考实现）的测试向量。
//!
//! 输入来自摄像头，一律视为不可信：所有长度都有上限，解析失败返回错误，不会 panic。

pub mod bytewords;
pub mod cbor;
pub mod crc32;
pub mod fountain;
pub mod registry;
mod sampler;
pub mod ur;
mod xoshiro;

/// 单条 UR 消息的最大长度（字节）。PSBT 远小于此值；防止恶意二维码耗尽内存。
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;
/// 多段 UR 的最大分片数。分片选择算法是 O(n²)，必须设上限。
pub const MAX_SEQ_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrError {
    /// bytewords 非法单词、长度不足或校验和不符
    Bytewords,
    /// CBOR 结构不合法、不是最短编码或不受支持
    Cbor,
    /// 不是 `ur:` 开头、路径段数不对、类型名含非法字符
    Format,
    /// 多段序号部分不合法
    Sequence,
    /// 分片与之前收到的不一致（换了另一组二维码）
    Inconsistent,
    /// 超出长度上限
    TooLarge,
    /// 拼合后的消息校验和不符
    Checksum,
    /// 类型不是预期的类型
    UnexpectedType,
}
