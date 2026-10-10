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

/// Safe execTransaction（operation = 0）包着的内层调用：(to, value, data)。
/// 不是该选择器、operation ≠ 0、或 ABI 偏移/长度越界时返回 None；DELEGATECALL 的拒签由 `decode` 负责。
pub fn safe_exec_inner(data: &[u8]) -> Option<([u8; 20], U256, &[u8])> {
    let (sel, args) = data.split_first_chunk::<4>()?;
    if *sel != SAFE_EXEC {
        return None;
    }
    let w = words(args);
    let [to, value, offset, operation, ..] = w.as_slice() else {
        return None;
    };
    if U256::from_be_bytes(operation).to_u64() != Some(0) {
        return None;
    }
    let to = addr(to)?;
    let offset = usize::try_from(U256::from_be_bytes(offset).to_u64()?).ok()?;
    let len_end = offset.checked_add(32)?;
    let len_word: &[u8; 32] = args.get(offset..len_end)?.try_into().ok()?;
    let len = usize::try_from(U256::from_be_bytes(len_word).to_u64()?).ok()?;
    let inner = args.get(len_end..len_end.checked_add(len)?)?;
    Some((to, U256::from_be_bytes(value), inner))
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
}
