//! 签名机一侧（feature `signing`，P2c-T3）：按 D34 的三种派生方案取出私钥，审查后签名。
//!
//! 会话里只保存 m/44'/501' 节点（三种方案的共同父节点）；每次签名临时派生子节点，用完即清零。

use crate::request::{scheme_of, SignRequest, SignType, Signature};
use crate::review::{review, Reviewed};
use crate::{Scheme, SolError};
use aw_common::secret::SecretBytes;
use aw_keys::slip10::Ed25519Node;

pub struct SolSigner {
    /// m/44'/501'
    root: Ed25519Node,
}

impl SolSigner {
    pub fn from_seed(seed: &SecretBytes<64>) -> Result<Self, SolError> {
        let root = Ed25519Node::master(seed)
            .derive(&[44, 501])
            .map_err(|_| SolError::Derivation)?;
        Ok(Self { root })
    }

    fn with_node<T>(
        &self,
        scheme: Scheme,
        index: u32,
        f: impl FnOnce(&Ed25519Node) -> Result<T, SolError>,
    ) -> Result<T, SolError> {
        let d = |_| SolError::Derivation;
        match scheme {
            Scheme::LedgerMain if index == 0 => f(&self.root),
            Scheme::LedgerMain => Err(SolError::PathMismatch),
            Scheme::LedgerLive => f(&self.root.child(index).map_err(d)?),
            Scheme::Phantom => f(&self.root.derive(&[index, 0]).map_err(d)?),
        }
    }

    pub fn public_key(&self, scheme: Scheme, index: u32) -> Result<[u8; 32], SolError> {
        self.with_node(scheme, index, |n| {
            n.public_key().map_err(|_| SolError::Derivation)
        })
    }

    /// 只审查不签名：路径必须是三种方案之一；请求声明的地址必须就是派生出的地址；消息必须通过审查
    pub fn review(&self, req: &SignRequest) -> Result<Reviewed, SolError> {
        if req.sign_type == Some(SignType::Message) {
            return Err(SolError::Unsupported);
        }
        let (scheme, index) = scheme_of(&req.path).ok_or(SolError::PathMismatch)?;
        let own = self.public_key(scheme, index)?;
        if req.address.is_some_and(|a| a != own) {
            return Err(SolError::AddressMismatch);
        }
        review(&req.sign_data, &own)
    }

    /// 审查后签名（拒签项直接返回错误）。是否需要用户确认高风险由调用方根据显示模型决定。
    pub fn sign(&self, req: &SignRequest) -> Result<(Reviewed, Signature), SolError> {
        let reviewed = self.review(req)?;
        let (scheme, index) = scheme_of(&req.path).ok_or(SolError::PathMismatch)?;
        let signature = self.with_node(scheme, index, |n| {
            n.sign(&req.sign_data).map_err(|_| SolError::Derivation)
        })?;
        Ok((
            reviewed,
            Signature {
                request_id: req.request_id,
                signature,
            },
        ))
    }
}
