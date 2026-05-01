#include <stdio.h>
#include <string.h>

static void w(FILE *f, const char *s) {
    fwrite(s, 1, strlen(s), f);
}

int main(void) {
    FILE *f = fopen("crypto_strings_adversarial.full.bin", "wb");
    if (!f) return 1;

    /* Valid BTC addresses embedded in noise */
    w(f, "noise-noise-1BoatSLRHtKNngkdXEeobR76b53LETtpy-more-noise\n");
    w(f, "xxxx1KFHE7w8BhaENAswwryaoccDb6qcT6Dbxxxx\n");

    /* Near-miss BTC (should NOT be detected) */
    w(f, "almost-btc-1BoatSLRHtKNngkdXEeobR76b53LETtp\n"); /* missing last char */
    w(f, "short-1KFHE7w8BhaENAswwryaoccDb6qcT6D\n"); /* too short */

    /* Valid ETH addresses (0x + 40 hex) */
    w(f, "prefix-0x12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab-suffix\n");
    w(f, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd\n");

    /* ETH inside obfuscated / reversed context */
    w(f, "reversed-ish-ba09fe87dc65ba43ba21x0{garbage}\n");
    w(f, "wrapped-[0x00112233445566778899aabbccddeeff00112233]-wrapped\n");

    /* Near-miss ETH (should NOT be detected) */
    w(f, "0x12ab34cd56ef78ab90cd12ef34ab56cd78ef90\n"); /* 39 hex chars */
    w(f, "0xG2ab34cd56ef78ab90cd12ef34ab56cd78ef90ab\n"); /* invalid hex */

    fclose(f);
    return 0;
}
