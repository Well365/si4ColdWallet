/*
 * aw_signer.h —— 签名机 Rust 核心的 C 接口（手写，决策 D2）。接口版本 3。
 *
 * 约定：
 *  - 返回 int32_t 的函数：0 = 成功，负数 = 错误码（见下）。
 *  - 由 Rust 分配的字节缓冲区，用完必须调用 aw_buf_free(ptr, len) 释放（先清零再释放）；
 *    len 必须与交出时完全一致。
 *  - 有输出参数的函数一进入就把输出置为 NULL/0；只有返回 AW_OK 时输出才有效。
 *  - 所有秘密（助记词、passphrase、私钥）只保存在 AwSession 内部；Swift 只持有不透明指针。
 *  - 句柄（AwSession / AwUrEncoder / AwUrDecoder）用对应的 *_free 释放，各只释放一次。
 */
#ifndef AW_SIGNER_H
#define AW_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AW_OK                    0
#define AW_ERR_NULL_POINTER     -1
#define AW_ERR_BAD_ARGUMENT     -2
#define AW_ERR_BAD_MNEMONIC     -3
#define AW_ERR_DERIVATION       -4
#define AW_ERR_SELFTEST        -10
#define AW_ERR_STATE           -11
#define AW_ERR_RNG_HEALTH      -12   /* 系统随机数没有通过健康检查 */
#define AW_ERR_DICE_TOO_FEW    -13   /* 纯骰子模式：12 词至少 50 次，24 词至少 100 次 */
#define AW_ERR_DICE_POOR       -14   /* 纯骰子模式：点数分布不像真实掷骰（某面过多、长串相同、有周期） */
#define AW_ERR_FINGERPRINT_MISMATCH -15  /* 解锁得到的指纹与预期不符（多半是 passphrase 输错）；助记词保留，可重输 */
#define AW_ERR_UR              -20
#define AW_ERR_UR_OTHER_SET    -21
#define AW_ERR_UR_TYPE         -22
#define AW_ERR_UNSUPPORTED_REQUEST -23  /* 扫到的二维码不是签名请求 */
#define AW_ERR_NEEDS_CONFIRMATION  -24  /* 含高风险警告，需用户确认后以 confirm_danger=1 重试 */
#define AW_ERR_TX              -30
/* 交易审查拒绝：AW_ERR_TX_REJECT_BASE - n，n 的含义见 Swift 侧 RejectReason */
#define AW_ERR_TX_REJECT_BASE -100
/* EVM 请求拒绝：AW_ERR_EVM_REJECT_BASE - n */
#define AW_ERR_EVM_REJECT_BASE -300

typedef struct AwSession AwSession;
typedef struct AwUrEncoder AwUrEncoder;
typedef struct AwUrDecoder AwUrDecoder;

/* ---- 基础 ---- */
uint32_t aw_abi_version(void);
int32_t  aw_selftest(void);                 /* 已知答案自检；失败必须阻止使用 */
void     aw_buf_free(uint8_t *ptr, size_t len);
const uint8_t *aw_wordlist_word(uint16_t idx, size_t *out_len);   /* 静态数据，勿释放 */

/* ---- 会话 ---- */
AwSession *aw_session_new(void);
void     aw_session_free(AwSession *s);
/* 混合模式：系统随机数（先做健康检查）+ 可选骰子 */
int32_t  aw_session_generate(AwSession *s, const uint8_t *system32,
                             const uint8_t *dice, size_t dice_len, uint8_t word_count);
/* 纯骰子模式（可独立验证）：熵 = SHA-256(骰子点数字符串)，见 tools/testvectors/verify_dice.py */
int32_t  aw_session_generate_dice(AwSession *s, const uint8_t *dice, size_t dice_len, uint8_t word_count);
int32_t  aw_session_set_words(AwSession *s, const uint16_t *idx, size_t n);
size_t   aw_session_word_count(const AwSession *s);
int32_t  aw_session_word_at(const AwSession *s, size_t i);
int32_t  aw_session_set_passphrase(AwSession *s, const uint8_t *p, size_t len);
/* 解锁时核对的预期指纹（大端 u32）；has = 0 表示不核对 */
int32_t  aw_session_expect_fingerprint(AwSession *s, uint8_t has, uint32_t fp);
/* 解锁成功后会话中的助记词、passphrase、预期指纹立即清除（word_count 变为 0）。
 * 设置了预期指纹而结果不符时返回 AW_ERR_FINGERPRINT_MISMATCH：清除 passphrase，保留助记词与预期指纹；
 * 调用方必须先重新 set_passphrase 再解锁（不重设时按空 passphrase 计算，仍会与预期指纹核对）。 */
int32_t  aw_session_unlock(AwSession *s, uint8_t testnet, const uint8_t *rand32);
uint32_t aw_session_fingerprint(const AwSession *s);
/* 第 index 个收款地址，JSON：{chain, path, address, note, explorers:[{name, url}]}。
 * explorers 只用于显示（签名机不联网，网址由用户在别的设备上输入）。
 * chain：0 BTC、1 EVM（ETH/BNB…）、2 SOL、3 DOGE、4 TRON、5 NEAR；SOL / NEAR 的 index < 20 */
int32_t  aw_session_address(const AwSession *s, uint32_t chain, uint32_t index, uint8_t **out_json, size_t *out_len);
/* chain：0 = BTC（BIP84），1 = EVM（m/44'/60'/0'） */
int32_t  aw_session_export_account(AwSession *s, uint32_t chain, AwUrEncoder **out);
/* 请求来自已收齐的解码器：crypto-psbt（BTC）或 eth-sign-request（EVM）。
 * 审查输出通用显示模型 JSON：{chain, network, title, rows:[{label,value,style}], warnings:[{level,text}]} */
int32_t  aw_session_review_ur(AwSession *s, const AwUrDecoder *d,
                              uint8_t **out_json, size_t *out_len);
/* 审查含高风险警告时必须 confirm_danger = 1（用户已在界面确认），否则返回 AW_ERR_NEEDS_CONFIRMATION */
int32_t  aw_session_sign_ur(AwSession *s, const AwUrDecoder *d, uint8_t confirm_danger, AwUrEncoder **out);

/* ---- 动画二维码 ---- */
AwUrDecoder *aw_ur_decoder_new(void);
void     aw_ur_decoder_free(AwUrDecoder *d);
int32_t  aw_ur_decoder_receive(AwUrDecoder *d, const uint8_t *s, size_t len); /* 1 = 完成 */
int32_t  aw_ur_decoder_progress(const AwUrDecoder *d, size_t *got, size_t *total);
int32_t  aw_ur_decoder_take_psbt(const AwUrDecoder *d, uint8_t **out, size_t *out_len);
void     aw_ur_encoder_free(AwUrEncoder *e);
int32_t  aw_ur_encoder_next(AwUrEncoder *e, uint8_t **out, size_t *out_len);   /* 大写 ASCII */
size_t   aw_ur_encoder_seq_len(const AwUrEncoder *e);

#ifdef __cplusplus
}
#endif

#endif /* AW_SIGNER_H */
