/*
 * Known-answer tests for the proof-of-work code in libalgos.a.
 *
 * Every expected value was cross-checked against an independent source:
 *  - sha256d, scrypt: Python's hashlib
 *  - x11: the Dash genesis block hash
 *  - cryptonight: the CryptoNote/Monero "slow hash" test vectors
 *  - all other sph-based algorithms: tpruvot/cpuminer-multi
 *
 * Usage:
 *   kat                      run all tests (exit status 1 on any failure)
 *   kat --hash ALGO HEX      print ALGO's hash of HEX (used by tests/mockpool.py)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Symbols libalgos.a expects the miner to provide. */
static struct work_restart restart_flags[1];
struct work_restart *work_restart = restart_flags;
bool aes_ni_supported = false;
bool opt_debug = false;

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;

	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i])
			return false;
		if (hash[i] < target[i])
			return true;
	}
	return true;
}

/* 80-byte block headers, in the byte order they are hashed. */
static const char *const header_hex[] = {
	/* Bitcoin genesis block */
	"0100000000000000000000000000000000000000000000000000000000000000"
	"000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
	"4b1e5e4a29ab5f49ffff001d1dac2b7c",
	/* Dash (X11) genesis block */
	"0100000000000000000000000000000000000000000000000000000000000000"
	"00000000c762a6567f3cc092f0684bb62b7e00a84890b990f07cc71a6bb58d64"
	"b98e02e0022ddb52f0ff0f1ec23fb901",
	/* fixed pseudo-random bytes */
	"f7c7701d0117e9f1f0ce9508abb11519c45a3c0407fcc90458a59f7b9d762617"
	"2eb61dd803807ce1f73f10aa8ae9771199ac1683940b45d38e10a54d7bd95a44"
	"3fa7ee3374e087aa04f18212015524b5",
};
#define N_HEADERS (sizeof(header_hex) / sizeof(header_hex[0]))

typedef void (*hash80_fn)(void *out, const void *in);
typedef int (*scan_fn)(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done);

static int s_scrypt(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	static unsigned char *scratchbuf;

	if (!scratchbuf)
		scratchbuf = scrypt_buffer_alloc(1024);
	return scanhash_scrypt(thr_id, pdata, scratchbuf, ptarget, max_nonce,
			hashes_done, 1024);
}

static void h_sha256d(void *out, const void *in) { sha256d(out, in, 80); }
static void h_scrypt(void *out, const void *in) { scrypt_hash(out, in, 1024); }
static void h_fresh(void *out, const void *in) { freshhash(out, in, 80); }

static const struct {
	const char *name;
	hash80_fn fn;
	scan_fn scan;
	const char *expected[N_HEADERS];	/* one per header above */
} algos[] = {
	{ "sha256d", h_sha256d, scanhash_sha256d, {
		"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
		"a4b09ec60478ce10b2bda154b349e5222e3b9a5fa8fdd9700fdd6eb044c49f08",
		"a95394b3a0fe69387a1c35badd4fce9a6e69ff38ecd4a3410ebf3861b18cd1b0" } },
	{ "scrypt", h_scrypt, s_scrypt, {
		"59053665189c5d648b11d47540603441c1eee666291879db5eb8e604a0d65856",
		"ac8d208a1c3f09932640257bed49f99ab191c6eced1c761c087dbce204c9ece8",
		"46bb54095dbc520928360df81c491fd3ba6ecddeed05f5070aa37f6f431d3774" } },
	{ "keccak", keccakhash, scanhash_keccak, {
		"1288180027a46738fca19f18d5bf419ac78bfd9d90a62122bb93787fa842105e",
		"20462a11d0b74f88b5d16cefa0fa2fb124f4f9e11e09a4f4b132f5785babda3f",
		"d27207d5fa967489709a51afc3bef9d889bd4191393f7f1f13cf63f28a94b5c7" } },
	{ "quark", quarkhash, scanhash_quark, {
		"ed68b5108e55f5361f4dfbcfeb40d976dc540a51619bc34c2c6f5b132c7213b2",
		"c608e6eefa3b298cfa864de5f71e0dc40d2ae8009d95b9c0a3d889c2a1d21a2b",
		"0bf07abe4f44776ef799543a3d4e8ca39588f66012fb14847ad90ac7c5f2dd87" } },
	{ "skein", skeinhash, scanhash_skein, {
		"d020fec8cd79ad48e5dd62d99521a64835c5692f79d9e1bcbda33d6580ed1271",
		"971c55d900af2196afa6e00d3345af017126f61186cef7fed25ae4510065f163",
		"6c3a072e11f3eb7971c3104f74a4e3f76330fc0fd0115f4c6ef6f9bde7fc16cb" } },
	{ "shavite3", inkhash, scanhash_ink, {
		"4213d207898171aa654c147cf8b6ae4c05f085da78ac45471e4dd7476114367e",
		"2c5eae99b7dc0716001764f1a4233dcdbab7ca12db46267d7bd4cffda9b81eb3",
		"9f82257a1ebd0d50bec720a15c1ca2bd8dba3b6c6ed4b430fbdea2c0f583c23f" } },
	{ "blake", blakehash, scanhash_blake, {
		"7f2b62ef43531a0ba5b34ae0ccd07671a38651943ddfec09cc80e5fa3424742b",
		"981c656a38986aea08eeecd4668d404c11c623b624c439bb51ad2ae4ed238c01",
		"bca5c682aba75d351ba5b5361534694299dc34bd3cdadc564bf58922ae8cadf0" } },
	{ "fresh", h_fresh, scanhash_fresh, {
		"f16be95bcff8abdef61a6fe73217fec622c136ffb85b9139026f7da86c066128",
		"8582ea22c018c2ac8317f231c09e8676e8c04a75a9475623d53d3fe843b17a52",
		"bdefaab230a7c4307437a8761dd35a099ddede447f247a0589fbfda842242dfe" } },
	{ "x11", x11hash, scanhash_x11, {
		"d90dbd33602755a7e3e6dab75b190405a73a596201a3db5af2172a0ac0153804",
		"b67a40f3cd5804437a108f105533739c37e6229bc1adcab385140b59fd0f0000",
		"a4ef5bc464437fafc7d54aec066a61a0ec016be327549655e35882c1fa7af88c" } },
	{ "x13", x13hash, scanhash_x13, {
		"c99f91e5dbd8158a1cee67797044972094df0afc4d5140f270e2c6f9bba520be",
		"bd7b68f858fceb974434d3147b27a05c4a4b8fad4cf1683c624acb3aff467564",
		"d66440fffb1963f7a8da54c6fbedb492439ba82149882ef8c529faf739eda079" } },
	{ "x14", x14hash, scanhash_x14, {
		"21bf0ddfe3117f203094cc1c8fc004fad4caf3e52141b52052b3419443a4328c",
		"53508d81d8d927ebbc468974126918056cd9faf720bbce4825d74cd6466a724c",
		"e9779dc652bc0d4e42151b89a96c33f1eb14b89d4870cd440e5536ca9bdee502" } },
	{ "x15", x15hash, scanhash_x15, {
		"215d26975dfcbd0045cbb5f3ee611124e1eaa15952dd8be86801b4f20133ad69",
		"a53723d85835af68793e08d00e3658f12ec476fe6f42121cd3b5c58e19386164",
		"b63178162027734fb758332d696cfd74675a093aaf0d426818905b0b12438755" } },
};
#define N_ALGOS (sizeof(algos) / sizeof(algos[0]))

/* CryptoNote "slow hash" vectors (variable-length input) */
static const struct {
	const char *input;
	const char *expected;
} cn_vectors[] = {
	{ "This is a test",
	  "a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605" },
	{ "de omnibus dubitandum",
	  "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5" },
	{ "abundans cautela non nocet",
	  "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4" },
	{ "caveat emptor",
	  "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87" },
	{ "ex nihilo nihil fit",
	  "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05" },
};

static int parse_hex(const char *hex, unsigned char *out, size_t max)
{
	size_t n = strlen(hex);

	if (n % 2 || n / 2 > max)
		return -1;
	for (size_t i = 0; i < n / 2; i++) {
		unsigned int b;
		if (sscanf(hex + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (unsigned char)b;
	}
	return (int)(n / 2);
}

static void to_hex(const unsigned char *in, size_t len, char *out)
{
	for (size_t i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", in[i]);
}

static int check(const char *what, const unsigned char *hash, const char *expected)
{
	char got[65];

	to_hex(hash, 32, got);
	if (strcmp(got, expected)) {
		printf("FAIL %s\n     expected %s\n     got      %s\n", what, expected, got);
		return 1;
	}
	printf("ok   %s\n", what);
	return 0;
}

/* compare two 256-bit little-endian numbers */
static int hash_cmp(const unsigned char *x, const unsigned char *y)
{
	for (int i = 31; i >= 0; i--)
		if (x[i] != y[i])
			return x[i] < y[i] ? -1 : 1;
	return 0;
}

static uint32_t le32(const unsigned char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
}

/*
 * Scan-loop test: pick the nonce with the lowest hash in a window, set
 * the share target to exactly that hash and check the scan loop reports
 * that nonce; then lower the target by one and check it reports nothing.
 * This catches wrong byte order, wrong nonce handling and any shortcut
 * filter that drops valid shares.
 */
static int scan_test(size_t a, const unsigned char *header)
{
	unsigned char h[80], hash[32], best[32];
	uint32_t pdata[32], target[8], base, best_nonce = 0;
	uint64_t done;
	char what[64];
	int i, rc, failures = 0;

	memcpy(h, header, 80);
	base = 0x10000000;
	memset(best, 0xff, 32);
	/* lowest hash among nonces base .. base+127 */
	for (uint32_t n = base; n < base + 128; n++) {
		be32enc(h + 76, n);
		algos[a].fn(hash, h);
		if (hash_cmp(hash, best) < 0) {
			memcpy(best, hash, 32);
			best_nonce = n;
		}
	}
	/* multi-lane scan loops may hash up to 31 nonces past max_nonce: none of
	 * them may be at or below the target either (rare; skip if so) */
	for (uint32_t n = best_nonce + 1; n <= best_nonce + 32; n++) {
		be32enc(h + 76, n);
		algos[a].fn(hash, h);
		if (hash_cmp(hash, best) <= 0) {
			printf("SKIP %s scan: ambiguous window\n", algos[a].name);
			return 0;
		}
	}

	be32enc(h + 76, best_nonce);
	for (i = 0; i < 20; i++)
		pdata[i] = be32dec(h + 4 * i);
	pdata[20] = 0x80000000;
	for (i = 21; i < 31; i++)
		pdata[i] = 0;
	pdata[31] = 0x00000280;
	for (i = 0; i < 8; i++)
		target[i] = le32(best + 4 * i);

	rc = algos[a].scan(0, pdata, target, best_nonce, &done);
	snprintf(what, sizeof(what), "%s scan finds share at target", algos[a].name);
	if (!rc || pdata[19] != best_nonce) {
		printf("FAIL %s (rc=%d nonce=%08x want %08x)\n", what, rc, pdata[19], best_nonce);
		failures++;
	} else
		printf("ok   %s\n", what);

	/* target - 1 */
	for (i = 0; i < 8; i++)
		if (target[i]-- != 0)
			break;
	for (i = 0; i < 20; i++)
		pdata[i] = be32dec(h + 4 * i);
	rc = algos[a].scan(0, pdata, target, best_nonce, &done);
	snprintf(what, sizeof(what), "%s scan rejects target - 1", algos[a].name);
	if (rc) {
		printf("FAIL %s (reported nonce %08x)\n", what, pdata[19]);
		failures++;
	} else
		printf("ok   %s\n", what);
	return failures;
}

/* CryptoNight scan: 64-bit target, nonce at bytes 39..42, any blob length */
static int cn_scan_test(size_t len)
{
	unsigned char blob[RPC2_MAX_BLOB], hash[32];
	uint32_t pdata[32], target[8], nonce = 0x12345678;
	uint64_t top, done;
	char what[64];
	int rc, failures = 0;

	for (size_t i = 0; i < len; i++)
		blob[i] = (unsigned char)(i * 7 + 3);
	le32enc(blob + 39, nonce);
	cryptonight_hash(hash, blob, len);
	top = ((uint64_t)le32(hash + 28) << 32) | le32(hash + 24);

	memset(pdata, 0, sizeof(pdata));
	memcpy(pdata, blob, len);
	memset(target, 0xff, sizeof(target));
	target[6] = (uint32_t)(top + 1);
	target[7] = (uint32_t)((top + 1) >> 32);
	rc = scanhash_cryptonight(0, pdata, len, target, nonce, &done);
	snprintf(what, sizeof(what), "cryptonight scan (%zu-byte blob) finds share", len);
	if (!rc || le32dec((unsigned char *)pdata + 39) != nonce) {
		printf("FAIL %s\n", what);
		failures++;
	} else
		printf("ok   %s\n", what);

	memcpy(pdata, blob, len);
	target[6] = (uint32_t)top;
	target[7] = (uint32_t)(top >> 32);
	rc = scanhash_cryptonight(0, pdata, len, target, nonce, &done);
	snprintf(what, sizeof(what), "cryptonight scan (%zu-byte blob) rejects target = hash", len);
	if (rc) {
		printf("FAIL %s\n", what);
		failures++;
	} else
		printf("ok   %s\n", what);
	return failures;
}

static int hash_cli(const char *algo, const char *hex)
{
	unsigned char in[256], out[64];
	char buf[129];
	int len = parse_hex(hex, in, sizeof(in));

	if (len < 0) {
		fprintf(stderr, "bad hex input\n");
		return 2;
	}
	if (!strcmp(algo, "cryptonight")) {
		cryptonight_hash(out, in, len);
	} else {
		size_t i;
		for (i = 0; i < N_ALGOS; i++)
			if (!strcmp(algos[i].name, algo))
				break;
		if (i == N_ALGOS || len != 80) {
			fprintf(stderr, "unknown algorithm or input is not 80 bytes\n");
			return 2;
		}
		algos[i].fn(out, in);
	}
	to_hex(out, 32, buf);
	puts(buf);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char header[N_HEADERS][80], hash[64];
	char what[128];
	int failures = 0;
	size_t a, h, v;

	init_quarkhash_contexts();
	init_blakehash_contexts();

	if (argc == 4 && !strcmp(argv[1], "--hash"))
		return hash_cli(argv[2], argv[3]);

	for (h = 0; h < N_HEADERS; h++)
		if (parse_hex(header_hex[h], header[h], 80) != 80)
			return 2;

	for (a = 0; a < N_ALGOS; a++)
		for (h = 0; h < N_HEADERS; h++) {
			memset(hash, 0, sizeof(hash));
			algos[a].fn(hash, header[h]);
			snprintf(what, sizeof(what), "%s header #%zu", algos[a].name, h);
			failures += check(what, hash, algos[a].expected[h]);
		}

	for (a = 0; a < N_ALGOS; a++)
		failures += scan_test(a, header[2]);

	for (v = 0; v < sizeof(cn_vectors) / sizeof(cn_vectors[0]); v++) {
		cryptonight_hash(hash, cn_vectors[v].input, strlen(cn_vectors[v].input));
		snprintf(what, sizeof(what), "cryptonight \"%s\"", cn_vectors[v].input);
		failures += check(what, hash, cn_vectors[v].expected);
	}

	failures += cn_scan_test(76);
	failures += cn_scan_test(77);

	printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
