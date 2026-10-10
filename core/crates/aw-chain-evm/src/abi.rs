//! 合约调用数据识别：只认少数常见函数，参数按 ABI 严格检查（长度精确、地址高位为零、布尔只能 0/1）。
//! 认不出的调用不猜测，原样显示并给出强警告（docs/01：未知合约调用）。

use crate::uint::U256;
use crate::EvmError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// 没有调用数据：原生币转账
    None,
    /// ERC-20 transfer(address,uint256)
    Transfer { to: [u8; 20], amount: U256 },
    /// approve(address,uint256)：ERC-20 的"额度"与 ERC-721 的"NFT 编号"共用这个选择器，离线无法区分
    Approve { spender: [u8; 20], amount: U256 },
    /// increaseAllowance(address,uint256)（OpenZeppelin ERC-20 扩展）
    IncreaseAllowance { spender: [u8; 20], amount: U256 },
    /// Permit2 approve(address token, address spender, uint160 amount, uint48 expiration)
    Permit2Approve {
        token: [u8; 20],
        spender: [u8; 20],
        amount: U256,
    },
    /// DAI 风格 permit(holder, spender, nonce, expiry, allowed, v, r, s)
    DaiPermit {
        holder: [u8; 20],
        spender: [u8; 20],
        allowed: bool,
    },
    /// transferFrom(address,address,uint256)：ERC-20 数量或 ERC-721 编号
    TransferFrom {
        from: [u8; 20],
        to: [u8; 20],
        amount: U256,
    },
    /// ERC-721 / ERC-1155 setApprovalForAll(address,bool)
    SetApprovalForAll { operator: [u8; 20], approved: bool },
    /// EIP-2612 permit(owner,spender,value,deadline,v,r,s)
    Permit {
        owner: [u8; 20],
        spender: [u8; 20],
        value: U256,
    },
    /// 无法识别：函数选择器 + 数据长度
    Unknown {
        selector: Option<[u8; 4]>,
        len: usize,
    },
}

const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const SET_APPROVAL_FOR_ALL: [u8; 4] = [0xa2, 0x2c, 0xb4, 0x65];
const PERMIT: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf];
const INCREASE_ALLOWANCE: [u8; 4] = [0x39, 0x50, 0x93, 0x51];
const PERMIT2_APPROVE: [u8; 4] = [0x87, 0x51, 0x7c, 0x45];
const DAI_PERMIT: [u8; 4] = [0x8f, 0xcb, 0xaf, 0x0c];
/// Safe approveHash(bytes32)：预先批准一笔看不到内容的多签交易（可能是 DELEGATECALL），默认拒签
const SAFE_APPROVE_HASH: [u8; 4] = [0xd4, 0xd9, 0xbd, 0xcd];
/// Safe（Gnosis Safe）execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
const SAFE_EXEC: [u8; 4] = [0x6a, 0x76, 0x12, 0x02];
/// Safe 模块入口 execTransactionFromModule(address,uint256,bytes,uint8) 与 …ReturnData：同样可以 DELEGATECALL
const SAFE_EXEC_FROM_MODULE: [u8; 4] = [0x46, 0x87, 0x21, 0xa7];
const SAFE_EXEC_FROM_MODULE_RETURN: [u8; 4] = [0x52, 0x29, 0x07, 0x3f];
/// Safe 对自身的管理函数：改所有者、阈值、模块、守卫、回退处理器、实现合约，或以多签名义签消息，
/// 任一都能移交多签控制权（D33）。含旧版（≤ 1.1.1）的 changeMasterCopy / signMessage。
pub const SAFE_ADMIN: [([u8; 4], &str); 11] = [
    ([0x61, 0x0b, 0x59, 0x25], "enableModule(address)"),
    ([0xe0, 0x09, 0xcf, 0xde], "disableModule(address,address)"),
    (
        [0x0d, 0x58, 0x2f, 0x13],
        "addOwnerWithThreshold(address,uint256)",
    ),
    (
        [0xf8, 0xdc, 0x5d, 0xd9],
        "removeOwner(address,address,uint256)",
    ),
    (
        [0xe3, 0x18, 0xb5, 0x2b],
        "swapOwner(address,address,address)",
    ),
    ([0x69, 0x4e, 0x80, 0xc3], "changeThreshold(uint256)"),
    ([0xe1, 0x9a, 0x9d, 0xd9], "setGuard(address)"),
    ([0xf0, 0x8a, 0x03, 0x23], "setFallbackHandler(address)"),
    ([0xe0, 0x68, 0xdf, 0x37], "setModuleGuard(address)"),
    ([0x7d, 0xe7, 0xed, 0xef], "changeMasterCopy(address)"),
    ([0x85, 0xa5, 0xaf, 0xfe], "signMessage(bytes)"),
];

/// 调用数据是否是 Safe 对自身的管理调用；返回函数签名
pub fn safe_admin_selector(data: &[u8]) -> Option<&'static str> {
    let sel = data.first_chunk::<4>()?;
    SAFE_ADMIN
        .iter()
        .find(|(s, _)| s == sel)
        .map(|(_, sig)| *sig)
}

fn words(args: &[u8]) -> Vec<[u8; 32]> {
    args.as_chunks::<32>().0.to_vec()
}

fn addr(w: &[u8; 32]) -> Option<[u8; 20]> {
    let (hi, lo) = w.split_at(12);
    if hi.iter().any(|&b| b != 0) {
        return None;
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(lo);
    Some(a)
}

fn boolean(w: &[u8; 32]) -> Option<bool> {
    match U256::from_be_bytes(w).to_u64()? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// 无符号整数参数必须能放进 `bits` 位（ABI 要求高位为零）
fn uint_bits(w: &[u8; 32], bits: usize) -> Option<U256> {
    let zero_bytes = (256 - bits) / 8;
    w.get(..zero_bytes)?
        .iter()
        .all(|&b| b == 0)
        .then(|| U256::from_be_bytes(w))
}

/// Safe 的三个执行入口（D33）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeEntry {
    /// execTransaction：所有者签名达到阈值后执行
    ExecTransaction,
    /// execTransactionFromModule：已启用的模块直接执行，不经过阈值
    FromModule,
    /// execTransactionFromModuleReturnData：同上，带返回数据
    FromModuleReturnData,
}

impl SafeEntry {
    fn from_selector(sel: &[u8; 4]) -> Option<Self> {
        match *sel {
            SAFE_EXEC => Some(Self::ExecTransaction),
            SAFE_EXEC_FROM_MODULE => Some(Self::FromModule),
            SAFE_EXEC_FROM_MODULE_RETURN => Some(Self::FromModuleReturnData),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::ExecTransaction => "execTransaction",
            Self::FromModule => "execTransactionFromModule",
            Self::FromModuleReturnData => "execTransactionFromModuleReturnData",
        }
    }

    pub fn is_module(self) -> bool {
        !matches!(self, Self::ExecTransaction)
    }
}

/// Safe 执行入口（operation = 0）的内容：内层调用与退款参数（模块入口没有退款参数，全为零）
pub struct SafeExec<'a> {
    pub entry: SafeEntry,
    pub to: [u8; 20],
    pub value: U256,
    pub data: &'a [u8],
    pub safe_tx_gas: U256,
    pub base_gas: U256,
    pub gas_price: U256,
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
}

/// ABI 动态 bytes：偏移字 → 长度字 → 内容；任何越界都返回 None（偏移指进头部也照 Safe 的解码方式取同一段）
fn dynamic_bytes<'a>(args: &'a [u8], offset: &[u8; 32]) -> Option<&'a [u8]> {
    let offset = usize::try_from(U256::from_be_bytes(offset).to_u64()?).ok()?;
    let len_end = offset.checked_add(32)?;
    let len_word: &[u8; 32] = args.get(offset..len_end)?.try_into().ok()?;
    let len = usize::try_from(U256::from_be_bytes(len_word).to_u64()?).ok()?;
    args.get(len_end..len_end.checked_add(len)?)
}

/// 解析 Safe 的执行入口。不是这三个选择器 → `Ok(None)`；operation ≠ 0 → `DelegateCall`；
/// 编码不规范（头部不完整、地址字高位非零、偏移或长度越界）→ `Parse`。
/// Safe 1.3/1.4 由 solc 0.7（ABI 编码器 v1）编译，会把地址字的高位截掉照常执行，
/// 所以签名机不能把不规范编码当作"未知调用"放过，只能拒签（审计复审 #1）。
pub fn safe_exec_inner(data: &[u8]) -> Result<Option<SafeExec<'_>>, EvmError> {
    let Some((sel, args)) = data.split_first_chunk::<4>() else {
        return Ok(None);
    };
    let Some(entry) = SafeEntry::from_selector(sel) else {
        return Ok(None);
    };
    let w = words(args);
    // 先看 operation：DELEGATECALL 的拒签理由比"编码不完整"更具体
    let [to, value, offset, operation, rest @ ..] = w.as_slice() else {
        return Err(EvmError::Parse);
    };
    if U256::from_be_bytes(operation).to_u64() != Some(0) {
        return Err(EvmError::DelegateCall);
    }
    let refund = match entry {
        SafeEntry::ExecTransaction => {
            let [safe_tx_gas, base_gas, gas_price, gas_token, refund_receiver, _signatures, ..] =
                rest
            else {
                return Err(EvmError::Parse);
            };
            Some((safe_tx_gas, base_gas, gas_price, gas_token, refund_receiver))
        }
        SafeEntry::FromModule | SafeEntry::FromModuleReturnData => None,
    };
    let to = addr(to).ok_or(EvmError::Parse)?;
    let (safe_tx_gas, base_gas, gas_price, gas_token, refund_receiver) = match refund {
        Some((s, b, p, t, r)) => (
            U256::from_be_bytes(s),
            U256::from_be_bytes(b),
            U256::from_be_bytes(p),
            addr(t).ok_or(EvmError::Parse)?,
            addr(r).ok_or(EvmError::Parse)?,
        ),
        None => (U256::ZERO, U256::ZERO, U256::ZERO, [0u8; 20], [0u8; 20]),
    };
    let inner = dynamic_bytes(args, offset).ok_or(EvmError::Parse)?;
    Ok(Some(SafeExec {
        entry,
        to,
        value: U256::from_be_bytes(value),
        data: inner,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
    }))
}

/// 识别调用数据。Safe 的 DELEGATECALL 与 approveHash 直接返回错误（默认拒签）。
pub fn decode(data: &[u8]) -> Result<Call, EvmError> {
    if data.is_empty() {
        return Ok(Call::None);
    }
    let unknown = || {
        let selector = data.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok());
        Call::Unknown {
            selector,
            len: data.len(),
        }
    };
    let Some((sel, args)) = data.split_first_chunk::<4>() else {
        return Ok(unknown());
    };
    let exact = |n: usize| args.len() == 32 * n;
    let w = words(args);
    let call = match (*sel, w.as_slice()) {
        (TRANSFER, [to, amount]) if exact(2) => addr(to).map(|to| Call::Transfer {
            to,
            amount: U256::from_be_bytes(amount),
        }),
        (APPROVE, [spender, amount]) if exact(2) => addr(spender).map(|spender| Call::Approve {
            spender,
            amount: U256::from_be_bytes(amount),
        }),
        (TRANSFER_FROM, [from, to, amount]) if exact(3) => match (addr(from), addr(to)) {
            (Some(from), Some(to)) => Some(Call::TransferFrom {
                from,
                to,
                amount: U256::from_be_bytes(amount),
            }),
            _ => None,
        },
        (INCREASE_ALLOWANCE, [spender, amount]) if exact(2) => {
            addr(spender).map(|spender| Call::IncreaseAllowance {
                spender,
                amount: U256::from_be_bytes(amount),
            })
        }
        (PERMIT2_APPROVE, [token, spender, amount, expiration]) if exact(4) => {
            match (
                addr(token),
                addr(spender),
                uint_bits(amount, 160),
                uint_bits(expiration, 48),
            ) {
                (Some(token), Some(spender), Some(amount), Some(_)) => Some(Call::Permit2Approve {
                    token,
                    spender,
                    amount,
                }),
                _ => None,
            }
        }
        (DAI_PERMIT, [holder, spender, _nonce, _expiry, allowed, _v, _r, _s]) if exact(8) => {
            match (addr(holder), addr(spender), boolean(allowed)) {
                (Some(holder), Some(spender), Some(allowed)) => Some(Call::DaiPermit {
                    holder,
                    spender,
                    allowed,
                }),
                _ => None,
            }
        }
        (SAFE_APPROVE_HASH, _) => return Err(EvmError::BlindApproval),
        (SET_APPROVAL_FOR_ALL, [op, flag]) if exact(2) => match (addr(op), boolean(flag)) {
            (Some(operator), Some(approved)) => {
                Some(Call::SetApprovalForAll { operator, approved })
            }
            _ => None,
        },
        (PERMIT, [owner, spender, value, _deadline, _v, _r, _s]) if exact(7) => {
            match (addr(owner), addr(spender)) {
                (Some(owner), Some(spender)) => Some(Call::Permit {
                    owner,
                    spender,
                    value: U256::from_be_bytes(value),
                }),
                _ => None,
            }
        }
        (s, [_to, _value, _data_offset, operation, ..])
            if s == SAFE_EXEC_FROM_MODULE || s == SAFE_EXEC_FROM_MODULE_RETURN =>
        {
            // 模块入口同样带 operation：DELEGATECALL 一样拒签（D33）
            match U256::from_be_bytes(operation).to_u64() {
                Some(0) => None,
                _ => return Err(EvmError::DelegateCall),
            }
        }
        (SAFE_EXEC, [_to, _value, _data_offset, operation, ..]) => {
            // operation：0 = CALL，1 = DELEGATECALL。后者可以改写多签合约本身，默认拒签
            match U256::from_be_bytes(operation).to_u64() {
                Some(0) => None, // 普通调用：按未知合约调用显示
                _ => return Err(EvmError::DelegateCall),
            }
        }
        _ => None,
    };
    Ok(call.unwrap_or_else(unknown))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use aw_common::hex;

    fn word_addr(a: u8) -> String {
        format!("{}{}", "00".repeat(12), format!("{a:02x}").repeat(20))
    }

    #[test]
    fn decodes_common_calls() {
        let amount = format!("{:064x}", 1_000_000u64);
        let d = hex::decode(&format!("a9059cbb{}{amount}", word_addr(0x22))).unwrap();
        assert_eq!(
            decode(&d).unwrap(),
            Call::Transfer {
                to: [0x22; 20],
                amount: U256::from_u64(1_000_000)
            }
        );
        let d = hex::decode(&format!("095ea7b3{}{}", word_addr(0x33), "ff".repeat(32))).unwrap();
        assert_eq!(
            decode(&d).unwrap(),
            Call::Approve {
                spender: [0x33; 20],
                amount: U256::MAX
            }
        );
        let d = hex::decode(&format!("a22cb465{}{:064x}", word_addr(0x44), 1)).unwrap();
        assert_eq!(
            decode(&d).unwrap(),
            Call::SetApprovalForAll {
                operator: [0x44; 20],
                approved: true
            }
        );
        assert_eq!(decode(&[]).unwrap(), Call::None);
    }

    #[test]
    fn strict_or_unknown() {
        // 地址高位非零：不按 transfer 显示
        let d = hex::decode(&format!("a9059cbb{}{:064x}", "11".repeat(32), 1)).unwrap();
        assert!(matches!(decode(&d).unwrap(), Call::Unknown { .. }));
        // 多一个字节
        let d = hex::decode(&format!("a9059cbb{}{:064x}00", word_addr(1), 1)).unwrap();
        assert!(matches!(decode(&d).unwrap(), Call::Unknown { .. }));
        // 布尔值不是 0/1
        let d = hex::decode(&format!("a22cb465{}{:064x}", word_addr(1), 2)).unwrap();
        assert!(matches!(decode(&d).unwrap(), Call::Unknown { .. }));
        // 不足 4 字节
        assert_eq!(
            decode(&[0xa9]).unwrap(),
            Call::Unknown {
                selector: None,
                len: 1
            }
        );
    }

    #[test]
    fn safe_delegatecall_rejected() {
        let head = |op: u64| {
            hex::decode(&format!(
                "6a761202{}{:064x}{:064x}{:064x}{}",
                word_addr(5),
                0,
                0x140,
                op,
                "00".repeat(32 * 6)
            ))
            .unwrap()
        };
        assert_eq!(decode(&head(1)), Err(EvmError::DelegateCall));
        assert!(matches!(decode(&head(0)).unwrap(), Call::Unknown { .. }));
        assert_eq!(decode(&head(7)), Err(EvmError::DelegateCall));
    }

    /// 选择器常量与函数签名的 keccak 一致（防止抄错一位）
    #[test]
    fn safe_selectors_match_signatures() {
        use crate::keccak::keccak256;
        let sel = |sig: &str| <[u8; 4]>::try_from(&keccak256(sig.as_bytes())[..4]).unwrap();
        assert_eq!(SAFE_EXEC, sel("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"));
        assert_eq!(
            SAFE_EXEC_FROM_MODULE,
            sel("execTransactionFromModule(address,uint256,bytes,uint8)")
        );
        assert_eq!(
            SAFE_EXEC_FROM_MODULE_RETURN,
            sel("execTransactionFromModuleReturnData(address,uint256,bytes,uint8)")
        );
        for (selector, sig) in &SAFE_ADMIN {
            assert_eq!(*selector, sel(sig), "{sig}");
        }
    }

    /// 畸形的 execTransaction 编码一律拒签（Parse），不 panic、不退化成"未知调用"（审计复审 #1）
    #[test]
    fn safe_exec_inner_refuses_malformed_encodings() {
        let word = |v: u64| U256::from_u64(v).to_be_bytes();
        let mut to = [0u8; 32];
        to[12..].fill(0x22);
        // 完整头部：to, value, offset, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, sigOffset
        let head = |offset: u64, operation: u64| -> Vec<u8> {
            let mut d = SAFE_EXEC.to_vec();
            for w in [
                to,
                word(0),
                word(offset),
                word(operation),
                word(0),
                word(0),
                word(0),
                [0u8; 32],
                [0u8; 32],
                word(352),
            ] {
                d.extend_from_slice(&w);
            }
            d
        };
        let with_len = |mut d: Vec<u8>, len: u64| {
            d.extend_from_slice(&word(len));
            d
        };
        let dirty = |mut d: Vec<u8>, word_index: usize| {
            if let Some(b) = d.get_mut(4 + 32 * word_index) {
                *b = 1;
            }
            d
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("头部不足", SAFE_EXEC.iter().copied().chain(to).collect()),
            ("offset 越界", head(10_000, 0)),
            ("offset = u64::MAX", head(u64::MAX, 0)),
            ("offset = u64::MAX-31", head(u64::MAX - 31, 0)),
            ("len 比剩余多 1", with_len(head(320, 0), 1)),
            ("len = u64::MAX", with_len(head(320, 0), u64::MAX)),
            ("to 高位非零", with_len(dirty(head(320, 0), 0), 0)),
            ("偏移字高位非零", with_len(dirty(head(320, 0), 2), 0)),
            ("gasToken 高位非零", with_len(dirty(head(320, 0), 7), 0)),
            (
                "refundReceiver 高位非零",
                with_len(dirty(head(320, 0), 8), 0),
            ),
        ];
        for (name, data) in cases {
            assert!(
                matches!(safe_exec_inner(&data), Err(EvmError::Parse)),
                "{name}"
            );
        }
        assert!(
            matches!(
                safe_exec_inner(&with_len(head(320, 1), 0)),
                Err(EvmError::DelegateCall)
            ),
            "operation = 1"
        );
        // 合法：内层数据长度 0
        let ok = with_len(head(320, 0), 0);
        let e = safe_exec_inner(&ok).unwrap().unwrap();
        assert!(e.data.is_empty() && e.gas_price.is_zero());
        assert_eq!(e.entry, SafeEntry::ExecTransaction);
        // 不是 Safe 入口：Ok(None)
        assert!(safe_exec_inner(&[0xa9, 0x05, 0x9c, 0xbb])
            .unwrap()
            .is_none());
    }

    /// 模块入口（4 个头部字）同样解析出内层调用；operation ≠ 0 拒签；头部不足按 Parse
    #[test]
    fn safe_module_entries_are_parsed() {
        let word = |v: u64| U256::from_u64(v).to_be_bytes();
        for sel in [SAFE_EXEC_FROM_MODULE, SAFE_EXEC_FROM_MODULE_RETURN] {
            let mut d = sel.to_vec();
            let mut to = [0u8; 32];
            to[12..].fill(0x22);
            d.extend_from_slice(&to);
            d.extend_from_slice(&word(7));
            d.extend_from_slice(&word(128));
            d.extend_from_slice(&word(0));
            d.extend_from_slice(&word(4));
            d.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            d.extend_from_slice(&[0u8; 28]);
            let e = safe_exec_inner(&d).unwrap().unwrap();
            assert!(e.entry.is_module());
            assert_eq!(e.to, [0x22; 20]);
            assert_eq!(e.value, U256::from_u64(7));
            assert_eq!(e.data, &[0xde, 0xad, 0xbe, 0xef]);
            assert!(e.gas_price.is_zero() && e.base_gas.is_zero());
            // operation = 2 → DELEGATECALL 一类，拒签
            let mut bad = d.clone();
            if let Some(b) = bad.get_mut(4 + 32 * 3 + 31) {
                *b = 2;
            }
            assert!(matches!(safe_exec_inner(&bad), Err(EvmError::DelegateCall)));
            // 只有 3 个头部字
            assert!(matches!(
                safe_exec_inner(d.get(..4 + 32 * 3).unwrap()),
                Err(EvmError::Parse)
            ));
        }
    }
}
