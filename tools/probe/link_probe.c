/*
 * 链接探针（检查 C8）：
 *  1. 以 C 方式调用签名机静态库的全部导出接口——少导出一个，链接就失败；
 *  2. 链接时开启 -dead_strip，得到"真实 App 会带上的代码"，再做导入白名单与反汇编检查；
 *  3. 在 iOS 模拟器里运行，确认自检、会话、导出账户、二维码编解码在 iOS 运行时上正确。
 */
#include <stdio.h>
#include <string.h>
#include "aw_signer.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } else { printf("ok:   %s\n", msg); } } while (0)

int main(void) {
    CHECK(aw_abi_version() == 4, "abi_version == 4");
    CHECK(aw_selftest() == AW_OK, "selftest");

    size_t wl = 0;
    const uint8_t *w = aw_wordlist_word(3, &wl);
    CHECK(w && wl == 5 && memcmp(w, "about", 5) == 0, "wordlist[3] == about");

    AwSession *s = aw_session_new();
    const uint16_t bad[12] = {0};
    CHECK(aw_session_set_words(s, bad, 12) == AW_ERR_BAD_MNEMONIC, "bad checksum rejected");
    const uint16_t words[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
    CHECK(aw_session_set_words(s, words, 12) == AW_OK, "set words");
    CHECK(aw_session_word_count(s) == 12 && aw_session_word_at(s, 11) == 3, "word access");
    const uint8_t rand32[32] = {0x11};
    /* 预期指纹 + 错误 passphrase：拒绝解锁且保留助记词；改回正确（空）passphrase 后解锁成功 */
    CHECK(aw_session_expect_fingerprint(s, 1, 0x73c5da0a) == AW_OK, "expect fingerprint");
    CHECK(aw_session_set_passphrase(s, (const uint8_t *)"typo", 4) == AW_OK, "wrong passphrase");
    CHECK(aw_session_unlock(s, 1, rand32) == AW_ERR_FINGERPRINT_MISMATCH, "fingerprint mismatch rejected");
    CHECK(aw_session_word_count(s) == 12, "words kept after mismatch");
    CHECK(aw_session_set_passphrase(s, (const uint8_t *)"", 0) == AW_OK, "passphrase");
    CHECK(aw_session_unlock(s, 1, rand32) == AW_OK, "unlock testnet");
    CHECK(aw_session_fingerprint(s) == 0x73c5da0a, "master fingerprint 73c5da0a");

    AwUrEncoder *enc = NULL;
    CHECK(aw_session_export_account(s, 0, &enc) == AW_OK && enc, "export account");
    CHECK(aw_ur_encoder_seq_len(enc) >= 1, "encoder seq_len");
    AwUrDecoder *d = aw_ur_decoder_new();
    int done = 0;
    for (int i = 0; i < 1000 && !done; i++) {
        uint8_t *f = NULL; size_t fl = 0;
        if (aw_ur_encoder_next(enc, &f, &fl) != AW_OK) break;
        int rc = aw_ur_decoder_receive(d, f, fl);
        if (i == 0) printf("      frame0 = %.*s\n", (int)(fl > 60 ? 60 : fl), f);
        aw_buf_free(f, fl);
        done = rc == 1;
    }
    CHECK(done, "account QR roundtrip");
    size_t got = 0, total = 0;
    CHECK(aw_ur_decoder_progress(d, &got, &total) == AW_OK, "progress");
    uint8_t *p = NULL; size_t pl = 7;
    CHECK(aw_ur_decoder_take_psbt(d, &p, &pl) == AW_ERR_UR_TYPE && p == NULL && pl == 0, "hdkey is not a psbt");
    CHECK(aw_session_review_ur(s, d, &p, &pl) == AW_ERR_UNSUPPORTED_REQUEST && p == NULL, "hdkey is not a request");
    AwUrEncoder *signed_enc = NULL;
    CHECK(aw_session_sign_ur(s, d, 0, &signed_enc) == AW_ERR_UNSUPPORTED_REQUEST && signed_enc == NULL, "hdkey not signed");
    AwUrDecoder *empty = aw_ur_decoder_new();
    CHECK(aw_session_review_ur(s, empty, &p, &pl) == AW_ERR_STATE, "incomplete scan rejected");
    aw_ur_decoder_free(empty);
    aw_ur_decoder_free(d);
    aw_ur_encoder_free(enc);
    AwUrEncoder *evm = NULL;
    CHECK(aw_session_export_account(s, 1, &evm) == AW_OK && evm, "export EVM account");
    aw_ur_encoder_free(evm);
    CHECK(aw_session_export_account(s, 9, &evm) == AW_ERR_BAD_ARGUMENT && evm == NULL, "unknown chain rejected");
    uint8_t stuck[32]; memset(stuck, 0x5a, 32);
    CHECK(aw_session_generate(s, stuck, (const uint8_t *)"123456", 6, 24) == AW_ERR_RNG_HEALTH, "stuck system RNG rejected");
    static const uint8_t sys32[32] = {0x3a, 0x91, 0x07, 0xc4, 0x5e, 0xe2, 0x18, 0x6d, 0xb9, 0x40, 0x2f, 0x83, 0xd6, 0x71, 0x0c, 0xa5,
                                      0x96, 0x2b, 0xf8, 0x54, 0x1e, 0xc7, 0x63, 0x3f, 0x8a, 0xd1, 0x05, 0x7c, 0xe9, 0x36, 0xbb, 0x42};
    CHECK(aw_session_generate(s, sys32, (const uint8_t *)"123456", 6, 24) == AW_OK && aw_session_word_count(s) == 24, "generate 24");
    char cyc[101]; for (int i = 0; i < 100; i++) cyc[i] = (char)('1' + i % 6); cyc[100] = 0;
    static const char rolls[] = "3261633433362244155334522333116113343614426455154252153355654526544131445632166514254645352524633213";
    CHECK(aw_session_generate_dice(s, (const uint8_t *)rolls, 49, 12) == AW_ERR_DICE_TOO_FEW, "too few dice rejected");
    CHECK(aw_session_generate_dice(s, (const uint8_t *)cyc, 100, 24) == AW_ERR_DICE_POOR, "periodic dice rejected");
    CHECK(aw_session_generate_dice(s, (const uint8_t *)rolls, 100, 24) == AW_OK, "dice-only generate 24");
    aw_session_free(s);
    aw_buf_free(NULL, 0);

    printf(failures == 0 ? "PROBE OK\n" : "PROBE FAILED (%d)\n", failures);
    return failures == 0 ? 0 : 1;
}
