# 审查清单：rust-bitcoin

> 自动生成于 2026-10-10。以下只列出需要人工判断的位置；**结论一栏必须由审查人填写**。

## 概况

| 项目 | 数量 |
|---|---|
| 文件总数 | 242 |
| Rust 源文件 | 121 |
| C/C++/汇编文件 | 0 |
| Cargo.toml | 9 |
| build.rs（构建期执行） | 2 |
| 过程宏 crate（构建期执行） | 0 |
| `unsafe` 出现次数 | 52 |

## 构建期会执行的代码

```
io/build.rs
bitcoin/build.rs
```

## 需要人工看的位置

### 二进制嵌入（涉及 12 个文件，最多列 40 行）

```
bitcoin/tests/serde.rs:47:    let segwit = include_bytes!(
bitcoin/tests/serde.rs:52:    let want = include_bytes!("data/serde/block_bincode");
bitcoin/tests/serde.rs:60:    let want = include_bytes!("data/serde/absolute_lock_time_blocks_bincode") as &[_];
bitcoin/tests/serde.rs:70:    let want = include_bytes!("data/serde/absolute_lock_time_seconds_bincode") as &[_];
bitcoin/tests/serde.rs:79:    let want = include_bytes!("data/serde/relative_lock_time_blocks_bincode") as &[_];
bitcoin/tests/serde.rs:88:    let want = include_bytes!("data/serde/relative_lock_time_seconds_bincode") as &[_];
bitcoin/tests/serde.rs:96:    let want = include_bytes!("data/serde/script_bincode") as &[_];
bitcoin/tests/serde.rs:102:    let ser = include_bytes!("data/serde/txin_ser");
bitcoin/tests/serde.rs:106:    let want = include_bytes!("data/serde/txin_bincode") as &[_];
bitcoin/tests/serde.rs:117:    let want = include_bytes!("data/serde/txout_bincode") as &[_];
bitcoin/tests/serde.rs:123:    let ser = include_bytes!("data/serde/transaction_ser");
bitcoin/tests/serde.rs:126:    let want = include_bytes!("data/serde/transaction_bincode") as &[_];
bitcoin/tests/serde.rs:139:    let want = include_bytes!("data/serde/witness_bincode") as &[_];
bitcoin/tests/serde.rs:145:    let s = include_str!("data/serde/public_key_hex");
bitcoin/tests/serde.rs:150:    let want = include_bytes!("data/serde/address_bincode") as &[_];
bitcoin/tests/serde.rs:156:    let s = include_str!("data/serde/extended_priv_key");
bitcoin/tests/serde.rs:159:    let want = include_bytes!("data/serde/extended_priv_key_bincode") as &[_];
bitcoin/tests/serde.rs:165:    let s = include_str!("data/serde/extended_pub_key");
bitcoin/tests/serde.rs:168:    let want = include_bytes!("data/serde/extended_pub_key_bincode") as &[_];
bitcoin/tests/serde.rs:174:    let s = include_str!("data/serde/ecdsa_sig_hex");
bitcoin/tests/serde.rs:181:    let want = include_bytes!("data/serde/ecdsa_sig_bincode") as &[_];
bitcoin/tests/serde.rs:187:    let s = include_str!("data/serde/control_block_hex");
bitcoin/tests/serde.rs:191:    let want = include_bytes!("data/serde/control_block_bincode") as &[_];
bitcoin/tests/serde.rs:199:    let want = include_bytes!("data/serde/child_number_bincode") as &[_];
bitcoin/tests/serde.rs:207:    let want = include_bytes!("data/serde/private_key_bincode") as &[_];
bitcoin/tests/serde.rs:213:    let s = include_str!("data/serde/public_key_hex");
bitcoin/tests/serde.rs:216:    let want = include_bytes!("data/serde/public_key_bincode") as &[_];
bitcoin/tests/serde.rs:270:            let s = include_str!("data/serde/extended_pub_key");
bitcoin/tests/serde.rs:319:    let want = include_bytes!("data/serde/psbt_bincode") as &[_];
bitcoin/tests/serde.rs:330:    let want = include_bytes!("data/serde/raw_pair_bincode") as &[_];
bitcoin/tests/serde.rs:342:    let want = include_bytes!("data/serde/proprietary_key_bincode") as &[_];
bitcoin/tests/serde.rs:348:    let s = include_str!("data/serde/taproot_sig_hex");
bitcoin/tests/serde.rs:355:    let want = include_bytes!("data/serde/taproot_sig_bincode") as &[_];
bitcoin/tests/serde.rs:368:    let want = include_bytes!("data/serde/taptree_bincode") as &[_];
bitcoin/tests/serde.rs:389:    let want = include_bytes!("data/serde/u256_bincode") as &[_];
bitcoin/tests/serde.rs:397:    let want = include_bytes!("data/serde/u256_bincode") as &[_];
bitcoin/tests/bip_174.rs:203:    let expected_psbt_hex = include_str!("data/create_psbt_hex");
bitcoin/tests/bip_174.rs:215:    let previous_tx_0 = include_str!("data/previous_tx_0_hex");
bitcoin/tests/bip_174.rs:216:    let previous_tx_1 = include_str!("data/previous_tx_1_hex");
bitcoin/tests/bip_174.rs:233:    let expected_psbt_hex = include_str!("data/update_1_psbt_hex");
```

### 网络（涉及 7 个文件，最多列 40 行）

```
hashes/src/lib.rs:32://! let mut reader: &[u8] = b"hello"; // in real code, this could be a `File` or `TcpStream`
io/src/bridge.rs:477:    impl Read for std::net::TcpStream
io/src/bridge.rs:481:    impl Write for std::net::TcpStream
io/src/bridge.rs:485:    impl Read for &'_ std::net::TcpStream
io/src/bridge.rs:489:    impl Write for &'_ std::net::TcpStream
io/src/error.rs:162:    /// A socket address could not be bound because the address is already in use elsewhere.
io/src/lib.rs:410:/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
io/src/lib.rs:436:/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
bitcoin/examples/handshake.rs:4:use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
bitcoin/examples/handshake.rs:33:    if let Ok(mut stream) = TcpStream::connect(address) {
bitcoin/src/p2p/message.rs:642:    use std::net::Ipv4Addr;
bitcoin/src/p2p/address.rs:12:use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
bitcoin/src/p2p/address.rs:37:    /// Create an address message for a socket
bitcoin/src/p2p/address.rs:38:    pub fn new(socket: &SocketAddr, services: ServiceFlags) -> Address {
bitcoin/src/p2p/address.rs:39:        let (address, port) = match *socket {
bitcoin/src/p2p/address.rs:46:    /// Extract socket address from an [Address] message.
bitcoin/src/p2p/address.rs:49:    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
bitcoin/src/p2p/address.rs:139:    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
bitcoin/src/p2p/address.rs:140:        Ok(iter::once(self.socket_addr()?))
bitcoin/src/p2p/address.rs:653:    /// Extract socket address from an [AddrV2Message] message.
bitcoin/src/p2p/address.rs:656:    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
bitcoin/src/p2p/address.rs:692:    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
bitcoin/src/p2p/address.rs:693:        Ok(iter::once(self.socket_addr()?))
bitcoin/src/p2p/address.rs:782:    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
bitcoin/src/p2p/address.rs:835:        assert!(matches!(full.socket_addr().unwrap(), SocketAddr::V4(_)));
bitcoin/src/p2p/address.rs:847:    fn test_socket_addr() {
bitcoin/src/p2p/address.rs:850:        assert_eq!(a4.socket_addr().unwrap(), s4);
bitcoin/src/p2p/address.rs:858:        assert_eq!(a6.socket_addr().unwrap(), s6);
bitcoin/src/p2p/address.rs:868:        assert!(addr.socket_addr().is_err());
```

### 进程与环境（涉及 3 个文件，最多列 40 行）

```
io/build.rs:2:    let rustc = std::env::var_os("RUSTC");
io/build.rs:4:    let output = std::process::Command::new(rustc)
io/src/bridge.rs:513:    impl Read for std::process::ChildStderr
io/src/bridge.rs:517:    impl Read for std::process::ChildStdout
io/src/bridge.rs:521:    impl Write for std::process::ChildStdin
io/src/bridge.rs:526:    impl Write for &'_ std::process::ChildStdin
bitcoin/build.rs:4:    let rustc = std::env::var_os("RUSTC");
bitcoin/build.rs:6:    let output = std::process::Command::new(rustc)
```

### 文件系统（涉及 3 个文件，最多列 40 行）

```
io/src/bridge.rs:451:    impl Read for std::fs::File
io/src/bridge.rs:455:    impl Write for std::fs::File
io/src/bridge.rs:459:    impl Read for &'_ std::fs::File
io/src/bridge.rs:463:    impl Write for &'_ std::fs::File
io/src/bridge.rs:468:    impl Read for std::sync::Arc<std::fs::File>
io/src/bridge.rs:473:    impl Write for std::sync::Arc<std::fs::File>
io/src/lib.rs:410:/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
io/src/lib.rs:436:/// For unbuffered readers (like [`std::fs::File`] or [`std::net::TcpStream`]), consider wrapping
bitcoin/tests/serde.rs:16://  use std::fs::File;
bitcoin/tests/serde.rs:20://  let mut file = File::create("/tmp/script_bincode").unwrap();
```

### 外部函数（涉及 0 个文件，最多列 40 行）

无

### C 代码中的系统调用（涉及 0 个文件，最多列 40 行）

无

## 二进制文件扫描

```
```

## 许可证文件

```
LICENSE
```

## 审查结论（人工填写）

| 项 | 结论 | 审查人 | 日期 |
|---|---|---|---|
| build.rs / 过程宏行为是否只做编译所需的事 | | | |
| 是否存在网络、进程、文件访问且非必要 | | | |
| 二进制文件是否全部为无害测试数据 | | | |
| 许可证是否兼容 MIT 项目 | | | |
| 是否同意引入 | | | |

## 初审记录（Claude，2026-10-10，待人工复核）

- `bitcoin/build.rs`、`io/build.rs`：各约 33 行，只执行 `$RUSTC --version` 并输出 `rust_v_1_NN` 编译条件；无网络、无文件写入。**可接受。**
- 我们实际编译的子 crate：bitcoin、hashes、io、units、base58。其余目录（fuzz、primitives 等）不进入构建。
- 依赖 `hex_lit` 0.1.1 无法追溯到上游源码，已用自写替代（决策 D11）。
