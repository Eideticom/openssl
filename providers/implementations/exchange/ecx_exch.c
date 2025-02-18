/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "crypto/ecx.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#ifdef S390X_EC_ASM
# include "s390x_arch.h"
#endif

#define __packed __attribute__((__packed__))

enum noload_security_cmd {
	NOLOAD_SECURITY_CMD_TRNG = 0,
	NOLOAD_SECURITY_CMD_MUL,
	NOLOAD_SECURITY_CMD_KEY_GEN,
	NOLOAD_SECURITY_CMD_DSA_SIGN,
	NOLOAD_SECURITY_CMD_DSA_VERIFY,
	NOLOAD_SECURITY_CMD_ECDH,
};

enum noload_security_mode {
	NOLOAD_SECURITY_MODE_NONE = -1,
	NOLOAD_SECURITY_MODE_192 = 0,
	NOLOAD_SECURITY_MODE_224,
	NOLOAD_SECURITY_MODE_256,
	NOLOAD_SECURITY_MODE_384,
	NOLOAD_SECURITY_MODE_521,
	NOLOAD_SECURITY_MODE_X25519,
};

#define NOLOAD_TYPE_SECURITY 7
#define NOLOAD_SUBTYPE_SECURITY_INBI 3

#define noload_strerror(msg) nlsd_strerror(msg)

#include <noloadsd/noload.h>
#include <noloadsd/noload_def.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>

struct noload_sec_cfg {
	uint8_t cmd;
	uint8_t mode;
	uint8_t curve;
	uint32_t rng_bytes; // top-most byte is ignored
	uint8_t reserved;
} __packed;

struct sec_keygen_odata {
	uint8_t pubX[72];
	uint8_t pubY[72];
	uint8_t priv[72];
} __packed;

struct sec_ecdsa_sign_idata {
	uint8_t hash[72];
	uint8_t priv_key[72];
} __packed;

struct sec_ecdsa_sign_odata {
	uint8_t sigr[72];
	uint8_t sigs[72];
	uint8_t randk[72];
} __packed;

struct sec_ecdsa_vfy_idata {
	uint8_t pubX[72];
	uint8_t pubY[72];
	uint8_t sigR[72];
	uint8_t sigS[72];
	uint8_t hash[72];
} __packed;

struct sec_ecdsa_vfy_odata {
	uint8_t fail;
	uint8_t reserved[71];
} __packed;


struct sec_keyexch_idata {
	uint8_t Qx[72];
	uint8_t Qy[72];
	uint8_t priv[72];
} __packed;

struct sec_keyexch_odata {
	uint8_t ss[72];
} __packed;

void *swapbytes(void *inp, size_t len);
void noload_openssl_cleanup(void);
enum noload_security_mode nid_to_mode(int nid);
enum noload_security_mode ECKEY_to_mode(const EC_KEY *eckey);
size_t alu_width_bits(enum noload_security_mode mode);
size_t alu_width_bytes(enum noload_security_mode mode);
int noload_ec_keygen(EC_KEY *key);
int noload_ecdsa_sign(int type, const unsigned char *dgst, int _dgstlen,
		      unsigned char *sig, unsigned int *siglen,
		      const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
int noload_ecdsa_verify(int type, const unsigned char *_dgst, int _dgstlen,
			const unsigned char *sig, int siglen, EC_KEY *eckey);
int noload_ecdh_compute_key(unsigned char *out, size_t *olen,
			    const EC_POINT *peer_pub_key, const EC_KEY *key);
static OSSL_FUNC_keyexch_newctx_fn x25519_newctx;
static OSSL_FUNC_keyexch_newctx_fn x448_newctx;
static OSSL_FUNC_keyexch_init_fn ecx_init;
static OSSL_FUNC_keyexch_set_peer_fn ecx_set_peer;
static OSSL_FUNC_keyexch_derive_fn ecx_derive;
static OSSL_FUNC_keyexch_freectx_fn ecx_freectx;
static OSSL_FUNC_keyexch_dupctx_fn ecx_dupctx;

static struct nlsd_worker *nlw = NULL;

static int noload_openssl_init(void)
{
	struct nlsd_type type = {
		.algo = (nlsd_le16_t){NOLOAD_TYPE_SECURITY},
		.subtype = (nlsd_le16_t){NOLOAD_SUBTYPE_SECURITY_INBI},
	};
	int ret;

	nlw = OPENSSL_malloc(sizeof(*nlw));
	if (!nlw)
		return -1;

	ret = nlsd_worker_init(nlw, type);
	if (ret)
		return -1;

	return 0;
}

static int sec_engine_noload_run_job(enum noload_security_cmd cmd,
			      enum noload_security_mode mode, void *ibuf,
			      size_t ilen, void *obuf, size_t olen)
{
	struct noload_sec_cfg cfg = {
		.cmd = cmd,
		.mode = mode,
		.curve = mode,
	};
	ssize_t ret;

	if (!nlw) {
		ret = noload_openssl_init();
		if (ret < 0)
			return ret;
	}

	ret = nlsd_worker_configure(nlw, &cfg, sizeof(cfg));
	if (ret < 0)
		return ret;

	ret = nlsd_worker_run(nlw, ibuf, ilen, obuf, olen);
	if (ret < 0)
		return -1;

	if (ret != olen) {
		fprintf(stderr, "Unexpected length received\n");
		errno = EIO;
		return -1;
	}

	return 0;
}

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes ECX_KEY structures, so
 * we use that here too.
 */

typedef struct {
    size_t keylen;
    ECX_KEY *key;
    ECX_KEY *peerkey;
} PROV_ECX_CTX;

static void *ecx_newctx(void *provctx, size_t keylen)
{
    PROV_ECX_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ECX_CTX));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->keylen = keylen;

    return ctx;
}

static void *x25519_newctx(void *provctx)
{
    printf("EXCH %s\n", __func__);
    return ecx_newctx(provctx, X25519_KEYLEN);
}

static void *x448_newctx(void *provctx)
{
    return ecx_newctx(provctx, X448_KEYLEN);
}

static int ecx_init(void *vecxctx, void *vkey,
                    ossl_unused const OSSL_PARAM params[])
{
    PROV_ECX_CTX *ecxctx = (PROV_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    printf("EXCH %s\n", __func__);
    if (!ossl_prov_is_running())
        return 0;

    if (ecxctx == NULL
            || key == NULL
            || key->keylen != ecxctx->keylen
            || !ossl_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ossl_ecx_key_free(ecxctx->key);
    ecxctx->key = key;

    return 1;
}

static int ecx_set_peer(void *vecxctx, void *vkey)
{
    PROV_ECX_CTX *ecxctx = (PROV_ECX_CTX *)vecxctx;
    ECX_KEY *key = vkey;

    printf("EXCH %s\n", __func__);
    if (!ossl_prov_is_running())
        return 0;

    if (ecxctx == NULL
            || key == NULL
            || key->keylen != ecxctx->keylen
            || !ossl_ecx_key_up_ref(key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    ossl_ecx_key_free(ecxctx->peerkey);
    ecxctx->peerkey = key;

    return 1;
}

static int nl_x25519_exch_derive(void *_ctx, unsigned char *secret,
				 size_t *secretlen, size_t outlen)
{
	struct sec_keyexch_idata idata = {};
	struct sec_keyexch_odata odata = {};
	PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)_ctx;
	int ret;

	printf("EXCH %s\n", __func__);
	if (!secret) {
		*secretlen = 32;
		return 1;
	}

	if (outlen < 32)
		return 0;

	memcpy(idata.priv, ctx->key->privkey, 32);
	memcpy(idata.Qx, ctx->peerkey->pubkey, 32);

	ret = sec_engine_noload_run_job(NOLOAD_SECURITY_CMD_ECDH,
			NOLOAD_SECURITY_MODE_X25519, &idata, sizeof(idata),
			&odata, sizeof(odata));
	if (ret) {
		fprintf(stderr, "%s: %s\n", __func__, noload_strerror(errno));
		return 0;
	}

	memcpy(secret, odata.ss, 32);
	*secretlen = 32;

	return 1;
}

static int ecx_derive(void *vecxctx, unsigned char *secret, size_t *secretlen,
                      size_t outlen)
{
    PROV_ECX_CTX *ecxctx = (PROV_ECX_CTX *)vecxctx;

    if (!ossl_prov_is_running())
        return 0;

    if (ecxctx->key == NULL
            || ecxctx->key->privkey == NULL
            || ecxctx->peerkey == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    if (!ossl_assert(ecxctx->keylen == X25519_KEYLEN
            || ecxctx->keylen == X448_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    if (secret == NULL) {
        *secretlen = ecxctx->keylen;
        return 1;
    }
    if (outlen < ecxctx->keylen) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ecxctx->keylen == X25519_KEYLEN) {
#ifdef S390X_EC_ASM
        if (OPENSSL_s390xcap_P.pcc[1]
                & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X25519)) {
            if (s390x_x25519_mul(secret, ecxctx->peerkey->pubkey,
                                 ecxctx->key->privkey) == 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
                return 0;
            }
        } else
#endif
        if (ossl_x25519(secret, ecxctx->key->privkey,
                        ecxctx->peerkey->pubkey) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
            return 0;
        }
    } else {
#ifdef S390X_EC_ASM
        if (OPENSSL_s390xcap_P.pcc[1]
                & S390X_CAPBIT(S390X_SCALAR_MULTIPLY_X448)) {
            if (s390x_x448_mul(secret, ecxctx->peerkey->pubkey,
                               ecxctx->key->privkey) == 0) {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
                return 0;
            }
        } else
#endif
        if (ossl_x448(secret, ecxctx->key->privkey,
                      ecxctx->peerkey->pubkey) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
            return 0;
        }
    }

    *secretlen = ecxctx->keylen;
    return 1;
}

static void ecx_freectx(void *vecxctx)
{
    printf("EXCH %s\n", __func__);
    PROV_ECX_CTX *ecxctx = (PROV_ECX_CTX *)vecxctx;

    ossl_ecx_key_free(ecxctx->key);
    ossl_ecx_key_free(ecxctx->peerkey);

    OPENSSL_free(ecxctx);
}

static void *ecx_dupctx(void *vecxctx)
{
    PROV_ECX_CTX *srcctx = (PROV_ECX_CTX *)vecxctx;
    PROV_ECX_CTX *dstctx;

    printf("EXCH %s\n", __func__);
    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    *dstctx = *srcctx;
    if (dstctx->key != NULL && !ossl_ecx_key_up_ref(dstctx->key)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(dstctx);
        return NULL;
    }

    if (dstctx->peerkey != NULL && !ossl_ecx_key_up_ref(dstctx->peerkey)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ossl_ecx_key_free(dstctx->key);
        OPENSSL_free(dstctx);
        return NULL;
    }

    return dstctx;
}

const OSSL_DISPATCH ossl_x25519_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))x25519_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void)) nl_x25519_exch_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ecx_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ecx_dupctx },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_x448_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))x448_newctx },
    { OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))ecx_init },
    { OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))ecx_derive },
    { OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))ecx_set_peer },
    { OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))ecx_freectx },
    { OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))ecx_dupctx },
    { 0, NULL }
};
