/*
 * 秘密残留回归测试（Rust 审查 MEDIUM 的复测，见决策 D16）：
 *  1. 阳性对照：在深层栈帧里写入已知字节，返回后扫描，必须能找到——证明扫描看得见这片栈；
 *  2. 基线：清零后扫描，所有秘密模式必须 0 次；
 *  3. 真实流程：纯骰子生成 → 导入测试助记词 → 解锁（含各链地址派生）→ 导出 BTC 与 EVM 账户，返回后再扫描，所有秘密模式必须 0 次。
 * 秘密模式（主私钥、链码、种子、账户私钥、HMAC 密钥派生值等）由 stack-scan.sh 用独立实现算出后经参数传入。
 * 用法：stack_scan 名称=64位十六进制 ...
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "aw_signer.h"

#define SCAN_BYTES (256 * 1024)
#define PLANT_BYTES (40 * 1024)
#define MAX_PATS 16

typedef struct {
    const char *name;
    uint8_t bytes[32];
} Pattern;

/* 放在静态区，避免模式本身出现在被扫描的栈上 */
static Pattern pats[MAX_PATS];
static size_t npats;

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int parse(const char *arg, Pattern *p) {
    const char *eq = strchr(arg, '=');
    if (!eq || strlen(eq + 1) != 64) return -1;
    p->name = arg;
    for (size_t i = 0; i < 32; i++) {
        int hi = hexval(eq[1 + 2 * i]), lo = hexval(eq[2 + 2 * i]);
        if (hi < 0 || lo < 0) return -1;
        p->bytes[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

__attribute__((noinline)) static void plant(const uint8_t *pat) {
    volatile uint8_t buf[PLANT_BYTES];
    for (size_t off = 0; off + 32 <= PLANT_BYTES; off += 4096)
        for (size_t i = 0; i < 32; i++) buf[off + i] = pat[i];
}

__attribute__((noinline)) static void clear(void) {
    volatile uint8_t buf[SCAN_BYTES];
    for (size_t i = 0; i < SCAN_BYTES; i++) buf[i] = 0;
}

__attribute__((noinline)) static int flow(void) {
    static const uint16_t idx[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
    static const uint8_t rand32[32] = {0x5a, 0x17, 0x33};
    AwSession *s = aw_session_new();
    if (!s) return AW_ERR_NULL_POINTER;
    AwUrEncoder *enc = NULL;
    /* 先走一遍纯骰子生成（熵的计算路径），再换成测试助记词 */
    static const char dice[] = "3261633433362244155334522333116113343614426455154252153355654526544131445632166514254645352524633213";
    int32_t rc = aw_session_generate_dice(s, (const uint8_t *)dice, 100, 24);
    if (rc == AW_OK) rc = aw_session_set_words(s, idx, 12);
    if (rc == AW_OK) rc = aw_session_unlock(s, 1, rand32);
    if (rc == AW_OK) rc = aw_session_export_account(s, 0, &enc);
    aw_ur_encoder_free(enc);
    enc = NULL;
    if (rc == AW_OK) rc = aw_session_export_account(s, 1, &enc);
    aw_ur_encoder_free(enc);
    aw_session_free(s);
    return rc;
}

/* 从调用方栈帧向下扫描 SCAN_BYTES 字节，统计模式出现次数（任意字节偏移） */
__attribute__((noinline)) static size_t count(const uint8_t *top, const uint8_t *pat) {
    const volatile uint8_t *lo = top - SCAN_BYTES;
    size_t n = 0;
    for (size_t i = 0; i + 32 <= SCAN_BYTES; i++) {
        size_t j = 0;
        while (j < 32 && lo[i + j] == pat[j]) j++;
        if (j == 32) n++;
    }
    return n;
}

int main(int argc, char **argv) {
    for (int a = 1; a < argc && npats < MAX_PATS; a++) {
        if (parse(argv[a], &pats[npats]) != 0) {
            printf("参数格式错误：%s\n", argv[a]);
            return 2;
        }
        npats++;
    }
    if (npats == 0) {
        printf("用法：stack_scan 名称=64位十六进制 ...\n");
        return 2;
    }
    const uint8_t *top = __builtin_frame_address(0);
    int bad = 0;

    plant(pats[0].bytes);
    size_t control = count(top, pats[0].bytes);
    printf("阳性对照（写入 %s 后扫描）：%zu 次\n", pats[0].name, control);
    if (control == 0) bad = 1;

    clear();
    for (size_t p = 0; p < npats; p++) {
        size_t n = count(top, pats[p].bytes);
        if (n) {
            printf("基线不干净：%s %zu 次\n", pats[p].name, n);
            bad = 1;
        }
    }

    int32_t rc = flow();
    printf("流程（导入→解锁→导出账户）返回 %d\n", rc);
    if (rc != AW_OK) bad = 1;
    for (size_t p = 0; p < npats; p++) {
        size_t n = count(top, pats[p].bytes);
        printf("  %-.*s：%zu 次\n", (int)(strchr(pats[p].name, '=') - pats[p].name), pats[p].name, n);
        if (n) bad = 1;
    }
    printf(bad ? "STACK SCAN FAIL\n" : "STACK SCAN OK\n");
    return bad;
}
