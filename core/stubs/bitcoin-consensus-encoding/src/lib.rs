//! 禁用桩：bitcoin-consensus-encoding 1.0.0。rust-bitcoin 新编码层的可选依赖；0.32 系列不需要
compile_error!("airgap-wallet：依赖 `bitcoin-consensus-encoding` 被禁止启用（决策 D12）。如确需使用，必须按规则 R1 从上游 git 引入并审查。");
