/*
 * Known-answer tests for the proof-of-work code in libalgos.a.
 *
 * Every expected value was cross-checked against an independent source:
 *  - sha256d, scrypt: Python's hashlib
 *  - x11: the Dash genesis block hash
 *  - sha256d, scrypt, skein, qubit, odo: real DigiByte blocks (block_vectors)
 *  - neoscrypt: real Feathercoin blocks, and Feathercoin Core's code
 *  - argon2d*: RFC 9106's test vector, and the reference implementation
 *    (as Myriad ships it)
 *  - odo: DigiByte Core's cipher test vectors, and its implementation for
 *    the synthetic headers
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Symbols libalgos.a expects the miner to provide. */
static struct work_restart restart_flags[1];
struct work_restart *work_restart = restart_flags;
bool aes_ni_supported = false;
bool opt_debug = false;

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	(void) prio;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

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

/* Argon2d, each variant */
#define ARGON2D_FNS(V, N) \
static void h_argon2d##N(void *out, const void *in) { argon2d_hash(out, in, V); } \
static int s_argon2d##N(int thr_id, uint32_t *pdata, const uint32_t *ptarget, \
	uint32_t max_nonce, uint64_t *hashes_done) \
{ \
	return scanhash_argon2d(thr_id, pdata, ptarget, V, max_nonce, hashes_done); \
}
ARGON2D_FNS(ARGON2D_4096, 4096)
ARGON2D_FNS(ARGON2D_500, 500)
ARGON2D_FNS(ARGON2D_250, 250)
ARGON2D_FNS(ARGON2D_16000, 16000)

/* Odocrypt with the main network's key for the header's time, as odohash() */
static int s_odo(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	return scanhash_odo(thr_id, pdata, ptarget,
			    odo_key(swab32(pdata[17]), ODO_INTERVAL_MAINNET),
			    max_nonce, hashes_done);
}

static const struct {
	const char *name;
	bool sha;		/* uses SHA-256: tested with and without SHA-NI */
	hash80_fn fn;
	scan_fn scan;
	const char *expected[N_HEADERS];	/* one per header above */
} algos[] = {
	{ "sha256d", true, h_sha256d, scanhash_sha256d, {
		"6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
		"a4b09ec60478ce10b2bda154b349e5222e3b9a5fa8fdd9700fdd6eb044c49f08",
		"a95394b3a0fe69387a1c35badd4fce9a6e69ff38ecd4a3410ebf3861b18cd1b0" } },
	{ "scrypt", true, h_scrypt, s_scrypt, {
		"59053665189c5d648b11d47540603441c1eee666291879db5eb8e604a0d65856",
		"ac8d208a1c3f09932640257bed49f99ab191c6eced1c761c087dbce204c9ece8",
		"46bb54095dbc520928360df81c491fd3ba6ecddeed05f5070aa37f6f431d3774" } },
	{ "keccak", false, keccakhash, scanhash_keccak, {
		"1288180027a46738fca19f18d5bf419ac78bfd9d90a62122bb93787fa842105e",
		"20462a11d0b74f88b5d16cefa0fa2fb124f4f9e11e09a4f4b132f5785babda3f",
		"d27207d5fa967489709a51afc3bef9d889bd4191393f7f1f13cf63f28a94b5c7" } },
	{ "quark", false, quarkhash, scanhash_quark, {
		"ed68b5108e55f5361f4dfbcfeb40d976dc540a51619bc34c2c6f5b132c7213b2",
		"c608e6eefa3b298cfa864de5f71e0dc40d2ae8009d95b9c0a3d889c2a1d21a2b",
		"0bf07abe4f44776ef799543a3d4e8ca39588f66012fb14847ad90ac7c5f2dd87" } },
	{ "skein", true, skeinhash, scanhash_skein, {
		"d020fec8cd79ad48e5dd62d99521a64835c5692f79d9e1bcbda33d6580ed1271",
		"971c55d900af2196afa6e00d3345af017126f61186cef7fed25ae4510065f163",
		"6c3a072e11f3eb7971c3104f74a4e3f76330fc0fd0115f4c6ef6f9bde7fc16cb" } },
	{ "shavite3", false, inkhash, scanhash_ink, {
		"4213d207898171aa654c147cf8b6ae4c05f085da78ac45471e4dd7476114367e",
		"2c5eae99b7dc0716001764f1a4233dcdbab7ca12db46267d7bd4cffda9b81eb3",
		"9f82257a1ebd0d50bec720a15c1ca2bd8dba3b6c6ed4b430fbdea2c0f583c23f" } },
	{ "blake", false, blakehash, scanhash_blake, {
		"7f2b62ef43531a0ba5b34ae0ccd07671a38651943ddfec09cc80e5fa3424742b",
		"981c656a38986aea08eeecd4668d404c11c623b624c439bb51ad2ae4ed238c01",
		"bca5c682aba75d351ba5b5361534694299dc34bd3cdadc564bf58922ae8cadf0" } },
	{ "fresh", false, h_fresh, scanhash_fresh, {
		"f16be95bcff8abdef61a6fe73217fec622c136ffb85b9139026f7da86c066128",
		"8582ea22c018c2ac8317f231c09e8676e8c04a75a9475623d53d3fe843b17a52",
		"bdefaab230a7c4307437a8761dd35a099ddede447f247a0589fbfda842242dfe" } },
	{ "x11", false, x11hash, scanhash_x11, {
		"d90dbd33602755a7e3e6dab75b190405a73a596201a3db5af2172a0ac0153804",
		"b67a40f3cd5804437a108f105533739c37e6229bc1adcab385140b59fd0f0000",
		"a4ef5bc464437fafc7d54aec066a61a0ec016be327549655e35882c1fa7af88c" } },
	{ "x13", false, x13hash, scanhash_x13, {
		"c99f91e5dbd8158a1cee67797044972094df0afc4d5140f270e2c6f9bba520be",
		"bd7b68f858fceb974434d3147b27a05c4a4b8fad4cf1683c624acb3aff467564",
		"d66440fffb1963f7a8da54c6fbedb492439ba82149882ef8c529faf739eda079" } },
	{ "x14", false, x14hash, scanhash_x14, {
		"21bf0ddfe3117f203094cc1c8fc004fad4caf3e52141b52052b3419443a4328c",
		"53508d81d8d927ebbc468974126918056cd9faf720bbce4825d74cd6466a724c",
		"e9779dc652bc0d4e42151b89a96c33f1eb14b89d4870cd440e5536ca9bdee502" } },
	{ "x15", false, x15hash, scanhash_x15, {
		"215d26975dfcbd0045cbb5f3ee611124e1eaa15952dd8be86801b4f20133ad69",
		"a53723d85835af68793e08d00e3658f12ec476fe6f42121cd3b5c58e19386164",
		"b63178162027734fb758332d696cfd74675a093aaf0d426818905b0b12438755" } },
	{ "qubit", false, qubithash, scanhash_qubit, {
		"24b015e6b3c7d19e4a9b5ad7dce01bb589086e1fad098f8f3d891a3eca3ec641",
		"f53c0bcbc5ba8db1792c74ea5a1eb7ee66783e24e4f4bffaccf591f86a49d842",
		"1fd95112326c4118bdc8326ffb859513092b1aff568769aa1b304e7c5aaad095" } },
	{ "odo", false, odohash, s_odo, {
		"ffdbde284c06c8187d104267fcf15228dc309299228daf62baa92b904c1048d3",
		"74972069d57a94bc2a750e726944f2c52249534434c7411f1bcb201d5b1635a9",
		"1dac4cbb5d3d1d1aed0f59d3469a4bf59173dfb320a0f36f002e23a4a9362b3e" } },
	{ "neoscrypt", false, neoscrypt_hash, scanhash_neoscrypt, {
		"d5565bd5b3875f583ca4eb212ea4ab15809f0895f0ff128bd1068da9e4bddb27",
		"8f8eea00585b98a86599601ef37a5554161562086c6342f4d4e2fcddadae4deb",
		"8c14059f6fde4f7f965164f22eb2ffdd14fed07551e192081d473b40b6a21ff8" } },
	{ "argon2d4096", false, h_argon2d4096, s_argon2d4096, {
		"209b8d5156e86decbf1c4976560c4e3f2ee1b146b5d955431ee403377b0ef8eb",
		"efcf784b1ae5a95dd15a1c6a9b52fe44c59ecd6f966c2e6a3d8355b1b49bab5b",
		"47a79c2c8d6290e319c187e32f1942e125c40aa65e7227d03b2453c2ba2a195c" } },
	{ "argon2d500", false, h_argon2d500, s_argon2d500, {
		"d63432f651456b36a27ee8c98e146b005c80e499d0931f2c9ca6ead68b3ff48f",
		"effc9ced570f3dead9906e606dd77cfa06a76400e1a9fc0e6632b66056ffbc1b",
		"0809cb55e03c7f642394f912b0a82ff840ae9844444394878510ddd8790e0118" } },
	{ "argon2d250", false, h_argon2d250, s_argon2d250, {
		"f4a2511de45745f14ca86031687a7e74f9ca3603959d88d6656112d922435f56",
		"d9467200bbdd84684b6cb7dd4088ffe7ca3a30b0785960f933a9771a50e9e937",
		"1748ece06fb1447f5868f0c2a13cdba60ab78182c90243db410567f0c20ce3e6" } },
	{ "argon2d16000", false, h_argon2d16000, s_argon2d16000, {
		"45d545f96a4d96344db68554279e8c865ed32e457539d853c9e9a7e48659d087",
		"3be5bb6383840ca90f18b5704114cd83d9fbffc1b7e80b90febb0a6ece05d1dc",
		"5304cf9ac518dd6fe2cdf3ad5be6a8556632ca0eeffd06e83e382eb8a3312e2f" } },
};
#define N_ALGOS (sizeof(algos) / sizeof(algos[0]))

/*
 * Real blocks: the header, and its proof-of-work hash, most significant
 * byte first as block explorers show hashes. The headers were checked
 * against their block hashes, which chain from one block to the next.
 * Explorers do not show Feathercoin's NeoScrypt hashes: those come from
 * Feathercoin Core's code, and each is below its block's target.
 */
static const struct {
	const char *what;
	const char *algo;
	const char *header;
	const char *pow;
} block_vectors[] = {
	{ "DigiByte block 12000000", "sha256d",
	  "02024020b4280e4d968527e4594b59ed4abad908a13657faa658ad633576d278"
	  "59226bbc43badc7960e2d361d5fb43070b13cbf47d68cd3b5c9a2622c59c3201"
	  "e4f1ecabcc13c85f4f9b0219c3dab44e",
	  "0000000000000000e231d6676909d4d54296d640d996453b6778cc8081239c1f" },
	{ "DigiByte block 11999999", "skein",
	  "0206002070a984f0cb24c667ff85a3f0038a54d109be25725a437ddbf7abc5f4"
	  "e77fe5a793fccdfa37bc5a987ae9b343fb51409ce44f4a35712af2fd156774aa"
	  "1d9cf9c3ca13c85f5a82031aaa244868",
	  "0000000000000149b07f6790b110c0d19a04e43aca08c460cb2aa30084eb2caa" },
	{ "DigiByte block 11999998", "qubit",
	  "02080020d87606b7ef16aeb26e3bb328b17a595a3198a985ae0da9a5e7e3eb43"
	  "e54b7ff2b650e5d37b588e6e4e4fbbd1b6228c8ab7a388e261e04863fd063589"
	  "bb19f071c613c85f4aa0041af1b5373d",
	  "0000000000000068c50fbf773bced2ae319ebc461f7635c59dd712835165344e" },
	{ "DigiByte block 11999997", "scrypt",
	  "0200002086d5a20406d7530ffc2998004a14e2a8ef618b79d54b203401000000"
	  "000000009760d9bc89809f459161fecfe70c46673aac2f2980df4143e46029be"
	  "2f2cff55c313c85fe7d2001b89c70c09",
	  "0000000000003fae858e91a5636704d4f1aa665db53c0cddf175b9cc5ecf9a86" },
	{ "DigiByte block 11999995", "odo",
	  "020e00203670628c63869e9135e07a4d3dea0f9d4e2a203848236d8c01000000"
	  "00000000965873e67854ef5a56dc315911f26c4222d2bd2c9741fc1ed1c5254e"
	  "cf11136cae13c85fd061181af8a005a6",
	  "000000000000072b3027c9ade646147ae57d1bab5cd6c1b2bfde9d7423bf2a50" },
	{ "Feathercoin block 6369117", "neoscrypt",
	  "040000209f6c175876f3896edc62293147eaf961aac07160134b8ff41256669d"
	  "236ab3e3f94ac17342f310122f6da79aed5443d6b743e811c709ef1f519e15ca"
	  "152762789735b86a3c4a481c0128aa1b",
	  "000000000d1bd0e9ddc982d3dcbfc021fabeca8e062056d9310dacf1a8a13dc8" },
	{ "Feathercoin block 6369118", "neoscrypt",
	  "0400002051c70d29c21b30b880b2b59a8319e5b2f49cec4b07baad3c093c3605"
	  "2d010e9a807b491fc3362dabfcad4ad03032b76e715a42a708698f8a982594aa"
	  "18f40f03b435b86a5ce1451c00182c39",
	  "0000000001e2c90039b3030ffe853761db261eda2d29b00c68dc94887b948ca3" },
	{ "Feathercoin block 6369119", "neoscrypt",
	  "00000020728f50ab7fc00c7254f8ca4e9c50f48a223aac6a59afa3509a7f976a"
	  "c9dd75e71d0c9d0661be8d8bc902e22ce3712417872edc05204c55279c1116da"
	  "716aef74be35b86a0c8d431c9cd9eff6",
	  "000000003b7a84f2e1b0dd11e724834c79e92b8aad72c2a072836615b1f3bc05" },
};

/* DigiByte Core's Odocrypt cipher vectors (src/test/crypto_tests.cpp);
 * NULL input: 80 bytes of its LongTestString() from offset 0x4ffb0 */
static const struct {
	uint32_t key;
	const char *input;
	const char *expected;
} odo_vectors[] = {
	{ 0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
	  "9724ebfef40d7808bc21b212d8645a1df4d7fc4a0d91ee8e7f747ca1383eaeb1bb264b3a3b1b1f19"
	  "a8d458616e9a19572e3ceb2f58773076e829a288c8fdb61ab619ffaa84a4ee752fea52dbb359620e" },
	{ 1, "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
	  "c659c70bd9335a0bec67e526cdf99569543ca7e258fad19d439fb8ada1bc68efa5553d270d236cf0"
	  "3b1c179c684cfc93ae15b3c239c11e384303785cc0d828114c28e08091f42ec707aba712fe999c68" },
	{ 0x80808080u, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqopqrpqrsqrstrstustuvtuvw",
	  "dc5d9757b16bfa425f527817ee88a070595a662474d06bb96b439e25bc3097fc7068ab9d934fcd19"
	  "c9587478dd9ab8f79f2c85175c51e49306135e561561725b0aa7a44366a1135ff93194da22d1e9ba" },
	{ 0x12345678, "As DigiByte relies on 80 byte header hashes, we want to have an example for that",
	  "13dddebb0d65daa0f3e4a5bd9a1b74af7ca5a7b32ef118fb1684b200e377ce504346adcd2354e818"
	  "bf530dd870386104f706f4fecde1cec5cee804aae2569821aa5b2db3ac048607be36714e2bce48c6" },
	{ 1729, NULL,
	  "de79362f40cf0c755b21cf30798fa828b21cba61222ebeccc5a1ee385183ff2a981926403529080f"
	  "6c5a650bb299770222e7dbc0bdd559f479fac21d08044d306513067f2bf6accdb8b55942a5430e1c" },
	{ 0xD59, "Mora labelled me Unknown Sample, which the overseer translated as Odo'ital......",
	  "a7dd19a7fcdf3b7c0a8da1765553d903ff42687fe2f36c3930b82d7a68e426a90f49f1fc4b06263d"
	  "cf95d70a1b436337586955ef61c976f97785da2d2c8144b6767f824d53dd518c2cfdce1e9bd74fe1" },
};

/* FIPS 180-2 SHA-256 test vectors (the last one needs two blocks, and
 * one with 55 bytes, the most that fits in one block with its padding) */
static const struct {
	const char *input;
	const char *expected;
} sha256_vectors[] = {
	{ "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
	{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1" },
};

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

/* index in algos[] of the algorithm called name; N_ALGOS if none */
static size_t find_algo(const char *name)
{
	size_t i;

	for (i = 0; i < N_ALGOS; i++)
		if (!strcmp(algos[i].name, name))
			break;
	return i;
}

/* a real block's proof-of-work hash */
static int block_test(size_t v, const char *impl)
{
	unsigned char header[80], hash[32], pow[32];
	char what[128], expected[65];
	size_t a = find_algo(block_vectors[v].algo);
	int i;

	if (a == N_ALGOS || parse_hex(block_vectors[v].header, header, 80) != 80
	    || parse_hex(block_vectors[v].pow, pow, 32) != 32) {
		printf("FAIL %s: bad test vector\n", block_vectors[v].what);
		return 1;
	}
	for (i = 0; i < 32; i++)	/* least significant byte first */
		sprintf(expected + 2 * i, "%02x", pow[31 - i]);
	algos[a].fn(hash, header);
	snprintf(what, sizeof(what), "%s, %s%s", block_vectors[v].what,
		 block_vectors[v].algo, impl);
	return check(what, hash, expected);
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
		size_t i = find_algo(algo);

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

	/* everything built on SHA-256 twice: with the portable code, and
	 * with the x86 SHA extensions when the CPU has them */
	for (int impl = 0; impl < 2; impl++) {
		const char *name = impl ? " (SHA-NI)" : "";

		if (sha256_use_shani(impl) != impl) {
			printf("skip SHA-256 (SHA-NI): this CPU or build has no SHA extensions\n");
			break;
		}
		for (v = 0; v < sizeof(sha256_vectors) / sizeof(sha256_vectors[0]); v++) {
			sha256_hash(hash, (const unsigned char *) sha256_vectors[v].input,
				    (int) strlen(sha256_vectors[v].input));
			snprintf(what, sizeof(what), "sha256%s \"%.20s\"", name,
				 sha256_vectors[v].input);
			failures += check(what, hash, sha256_vectors[v].expected);
		}
		for (a = 0; a < N_ALGOS; a++) {
			if (impl && !algos[a].sha)
				continue;
			for (h = 0; h < N_HEADERS; h++) {
				memset(hash, 0, sizeof(hash));
				algos[a].fn(hash, header[h]);
				snprintf(what, sizeof(what), "%s%s header #%zu",
					 algos[a].name, name, h);
				failures += check(what, hash, algos[a].expected[h]);
			}
		}
		for (v = 0; v < sizeof(block_vectors) / sizeof(block_vectors[0]); v++)
			if (!impl || algos[find_algo(block_vectors[v].algo)].sha)
				failures += block_test(v, name);
		for (a = 0; a < N_ALGOS; a++)
			if (!impl || algos[a].sha)
				failures += scan_test(a, header[2]);
	}
	sha256_use_shani(true);

	for (v = 0; v < sizeof(odo_vectors) / sizeof(odo_vectors[0]); v++) {
		unsigned char in[80], out[80], want[80];

		if (odo_vectors[v].input)
			memcpy(in, odo_vectors[v].input, 80);
		else	/* LongTestString(): i, i >> 4, ... i >> 16, from i = 65520 */
			for (h = 0; h < 80; h++)
				in[h] = (unsigned char) ((65520 + h / 5) >> (4 * (h % 5)));
		odo_encrypt_block(out, in, odo_vectors[v].key);
		parse_hex(odo_vectors[v].expected, want, 80);
		snprintf(what, sizeof(what), "odocrypt cipher, key %08x",
			 (unsigned) odo_vectors[v].key);
		if (memcmp(out, want, 80)) {
			printf("FAIL %s\n", what);
			failures++;
		} else
			printf("ok   %s\n", what);
	}

	/* both CryptoNight implementations: portable C, and AES-NI when the
	 * CPU has it */
	for (int impl = 0; impl < 2; impl++) {
		const char *name = impl ? "AES-NI" : "portable";

		if (impl && !cryptonight_cpu_has_aesni()) {
			printf("skip cryptonight (AES-NI): this CPU or build has no AES-NI\n");
			break;
		}
		aes_ni_supported = impl;
		for (v = 0; v < sizeof(cn_vectors) / sizeof(cn_vectors[0]); v++) {
			cryptonight_hash(hash, cn_vectors[v].input, strlen(cn_vectors[v].input));
			snprintf(what, sizeof(what), "cryptonight (%s) \"%s\"", name,
				 cn_vectors[v].input);
			failures += check(what, hash, cn_vectors[v].expected);
		}
		failures += cn_scan_test(76);
		failures += cn_scan_test(77);
	}
	aes_ni_supported = false;

	/* every other NeoScrypt implementation this processor can run (the
	 * best one ran above) */
	{
		static const char *const impl_names[] = {
			"portable", "SSE2", "AVX2", "AVX-512"
		};
		size_t neo = find_algo("neoscrypt");
		int best = neoscrypt_use_impl(-1);

		for (int impl = 0; impl < best; impl++) {
			char label[32];

			snprintf(label, sizeof(label), " (%s)", impl_names[impl]);
			if (neoscrypt_use_impl(impl) != impl) {
				printf("skip neoscrypt (%s): not for this processor or build\n",
				       impl_names[impl]);
				continue;
			}
			for (h = 0; h < N_HEADERS; h++) {
				algos[neo].fn(hash, header[h]);
				snprintf(what, sizeof(what), "neoscrypt%s header #%zu",
					 label, h);
				failures += check(what, hash, algos[neo].expected[h]);
			}
			for (v = 0; v < sizeof(block_vectors) / sizeof(block_vectors[0]); v++)
				if (!strcmp(block_vectors[v].algo, "neoscrypt"))
					failures += block_test(v, label);
			failures += scan_test(neo, header[2]);
		}
		neoscrypt_use_impl(-1);
	}

	/* Argon2d: RFC 9106's test vector, and every implementation this
	 * processor can run (the best one ran above) */
	{
		static const char *const impl_names[] = { "plain", "AVX2" };
		static const char *const variants[] = {
			"argon2d4096", "argon2d500", "argon2d250", "argon2d16000"
		};
		uint8_t pwd[32], salt[16], secret[8], ad[12];
		int best = argon2d_use_impl(-1);

		memset(pwd, 1, sizeof(pwd));
		memset(salt, 2, sizeof(salt));
		memset(secret, 3, sizeof(secret));
		memset(ad, 4, sizeof(ad));
		for (int impl = best; impl >= 0; impl--) {
			char label[32];

			if (argon2d_use_impl(impl) != impl) {
				printf("skip argon2d (%s): not for this processor or build\n",
				       impl_names[impl]);
				continue;
			}
			snprintf(label, sizeof(label), " (%s)", impl_names[impl]);
			argon2d_raw(hash, 32, pwd, 32, salt, 16, secret, 8, ad, 12,
				    3, 32, 4, 0x13);
			snprintf(what, sizeof(what), "argon2d%s RFC 9106", label);
			failures += check(what, hash,
				"512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
			if (impl == best)
				continue;
			for (v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
				a = find_algo(variants[v]);
				for (h = 0; h < N_HEADERS; h++) {
					algos[a].fn(hash, header[h]);
					snprintf(what, sizeof(what), "%s%s header #%zu",
						 algos[a].name, label, h);
					failures += check(what, hash, algos[a].expected[h]);
				}
			}
			failures += scan_test(find_algo("argon2d4096"), header[2]);
		}
		argon2d_use_impl(-1);
	}

	printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
