/*
 * aw_watch.h —— 观察机 Rust 核心的 C 接口（手写，决策 D2）。接口版本 2。
 * 本库只含公钥与交易构造代码，不含任何私钥代码。约定同 aw_signer.h。
 */
#ifndef AW_WATCH_H
#define AW_WATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AW_OK                    0
#define AW_ERR_NULL_POINTER     -1
#define AW_ERR_BAD_ARGUMENT     -2
#define AW_ERR_STATE           -11
#define AW_ERR_UR              -20
#define AW_ERR_UR_OTHER_SET    -21
#define AW_ERR_UR_TYPE         -22
#define AW_ERR_TX              -30
#define AW_ERR_TX_REJECT_BASE -100
#define AW_ERR_EVM_REJECT_BASE -300
/* Solana 请求拒绝：AW_ERR_SOL_REJECT_BASE - n（P2c） */
#define AW_ERR_SOL_REJECT_BASE -400

typedef struct AwWatch AwWatch;
typedef struct AwPending AwPending;
typedef struct AwUrEncoder AwUrEncoder;
typedef struct AwUrDecoder AwUrDecoder;
typedef struct AwEvmAccount AwEvmAccount;
typedef struct AwEvmPending AwEvmPending;

uint32_t aw_watch_abi_version(void);
void     aw_buf_free(uint8_t *ptr, size_t len);

/* ---- 账户 ---- */
int32_t  aw_watch_from_decoder(const AwUrDecoder *d, AwWatch **out);
int32_t  aw_watch_from_ur(const uint8_t *s, size_t len, AwWatch **out);
int32_t  aw_watch_to_ur(const AwWatch *w, uint8_t **out, size_t *out_len);
void     aw_watch_free(AwWatch *w);
uint32_t aw_watch_fingerprint(const AwWatch *w);
uint8_t  aw_watch_is_testnet(const AwWatch *w);
int32_t  aw_watch_address(const AwWatch *w, uint8_t change, uint32_t index, uint8_t **out, size_t *out_len);

/* ---- 付款 ----
 * utxos：u32 个数，然后每个 u8 change、u32 index、u32 vout、u32 交易长度、交易原始字节（全部大端） */
int32_t  aw_watch_build_payment(const AwWatch *w, const uint8_t *utxos, size_t utxos_len,
                                const uint8_t *to, size_t to_len, uint64_t amount_sat,
                                uint64_t fee_rate_sat_vb, uint32_t change_index,
                                AwPending **out_pending, uint8_t **out_json, size_t *out_json_len);
int32_t  aw_pending_encoder(const AwPending *p, AwUrEncoder **out);
int32_t  aw_pending_finalize(const AwWatch *w, const AwPending *p, const uint8_t *signed_psbt, size_t len,
                             uint8_t **out_tx_hex, size_t *out_len);
void     aw_pending_free(AwPending *p);

/* ---- EVM（ETH、BNB Smart Chain 等，账户 m/44'/60'/0'）----
 * 金额一律为 32 字节大端整数（最小单位：wei 或代币最小单位）。 */
int32_t  aw_evm_from_decoder(const AwUrDecoder *d, AwEvmAccount **out);
int32_t  aw_evm_from_ur(const uint8_t *s, size_t len, AwEvmAccount **out);
int32_t  aw_evm_to_ur(const AwEvmAccount *a, uint8_t **out, size_t *out_len);
void     aw_evm_free(AwEvmAccount *a);
uint32_t aw_evm_fingerprint(const AwEvmAccount *a);
int32_t  aw_evm_address(const AwEvmAccount *a, uint32_t index, uint8_t **out, size_t *out_len);
int32_t  aw_evm_parse_amount(const uint8_t *s, size_t len, uint32_t decimals, uint8_t *out32);
int32_t  aw_evm_format_quantity(const uint8_t *hex, size_t len, uint32_t decimals, uint8_t **out, size_t *out_len);
/* token_len == 0：原生币；否则 token 为 ERC-20 合约地址文本。out_json 为与签名机相同的显示模型 */
int32_t  aw_evm_build_transfer(const AwEvmAccount *a, uint32_t index, uint64_t chain_id, uint64_t nonce,
                               const uint8_t *max_priority_fee32, const uint8_t *max_fee32, uint64_t gas_limit,
                               const uint8_t *to, size_t to_len, const uint8_t *value32,
                               const uint8_t *token, size_t token_len, const uint8_t *request_id16,
                               AwEvmPending **out_pending, uint8_t **out_json, size_t *out_json_len);
int32_t  aw_evm_pending_encoder(const AwEvmPending *p, AwUrEncoder **out);
/* d：已收齐 eth-signature 的解码器；输出 "0x…" 原始交易，可直接 eth_sendRawTransaction */
int32_t  aw_evm_pending_finalize(const AwEvmAccount *a, const AwEvmPending *p, const AwUrDecoder *d,
                                 uint8_t **out_hex, size_t *out_len);
void     aw_evm_pending_free(AwEvmPending *p);
/* 消息签名请求：kind 0 = personal_sign（text 为 UTF-8 消息），1 = EIP-712（text 为 eth_signTypedData_v4 的 JSON）。
 * chain_id 为 0 表示不声明链；EIP-712 域里的链 ID 与之不符时拒绝。out_json 为与签名机相同的显示模型。
 * 签名回来后用 aw_evm_pending_finalize 核对，输出 "0x…" 65 字节签名（v 为 27/28） */
int32_t  aw_evm_build_message(const AwEvmAccount *a, uint32_t index, uint8_t kind, const uint8_t *text, size_t len,
                              uint64_t chain_id, const uint8_t *request_id16,
                              AwEvmPending **out_pending, uint8_t **out_json, size_t *out_json_len);
/* "0x…" 原始交易的交易哈希（核对节点返回值） */
int32_t  aw_evm_tx_hash(const uint8_t *hex, size_t len, uint8_t **out, size_t *out_len);
/* 手续费三档（D35）。EIP-1559 链：has_base_fee = 1，base_fee 为下一区块基础费，rewards 为 eth_feeHistory
 * 的 reward 展平（每个区块 3 个：10/50/90 百分位，rewards_len 为 3 的倍数且 ≤ 192），node_price 为
 * eth_maxPriorityFeePerGas；旧式链：has_base_fee = 0、rewards_len = 0，node_price 为 eth_gasPrice。
 * 输出 JSON 数组（慢、标准、快）：{speed, label, max_priority_fee, max_fee（wei 整数）, max_priority_gwei,
 * max_fee_gwei, max_cost（gas_limit × max_fee，原生币单位文本）} */
int32_t  aw_evm_fee_tiers(uint8_t has_base_fee, uint64_t base_fee, const uint64_t *rewards, size_t rewards_len,
                          uint64_t node_price, uint64_t gas_limit, uint8_t **out_json, size_t *out_len);
/* 构造前核对余额（D35）：native_hex / token_hex 为 JSON-RPC 十六进制数量（原生币转账 token_len = 0）；
 * value32、max_fee32 为 32 字节大端整数。原生币不够付"金额 + gas_limit × max_fee"（代币转账只算手续费）
 * 返回 AW_ERR_EVM_NATIVE_SHORT；代币不够返回 AW_ERR_EVM_TOKEN_SHORT */
#define AW_ERR_EVM_NATIVE_SHORT (AW_ERR_TX_REJECT_BASE - 19)
#define AW_ERR_EVM_TOKEN_SHORT  (AW_ERR_TX_REJECT_BASE - 21)
int32_t  aw_evm_check_funds(const uint8_t *native_hex, size_t native_len, const uint8_t *token_hex, size_t token_len,
                            const uint8_t *value32, uint64_t gas_limit, const uint8_t *max_fee32);

/* ---- 动画二维码 ---- */
AwUrDecoder *aw_ur_decoder_new(void);
void     aw_ur_decoder_free(AwUrDecoder *d);
int32_t  aw_ur_decoder_receive(AwUrDecoder *d, const uint8_t *s, size_t len);
int32_t  aw_ur_decoder_progress(const AwUrDecoder *d, size_t *got, size_t *total);
int32_t  aw_ur_decoder_take_psbt(const AwUrDecoder *d, uint8_t **out, size_t *out_len);
void     aw_ur_encoder_free(AwUrEncoder *e);
int32_t  aw_ur_encoder_next(AwUrEncoder *e, uint8_t **out, size_t *out_len);
size_t   aw_ur_encoder_seq_len(const AwUrEncoder *e);

#ifdef __cplusplus
}
#endif

#endif /* AW_WATCH_H */
