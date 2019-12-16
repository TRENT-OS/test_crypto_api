/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "LibDebug/Debug.h"

#include <string.h>

// From mbedtls test suite; has very small keylength, do not use for anything
// other than testing!!
static const SeosCryptoApi_Key_Data dhPrvData =
{
    .type = SeosCryptoApi_Key_TYPE_DH_PRV,
    .data.dh.prv = {
        .params = {
            .pBytes = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen   = 13,
            .gBytes = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen   = 13,
        },
        .xBytes = {0x11, 0x46, 0xbc, 0x69, 0xaf, 0x6c, 0x32, 0xca, 0xfa, 0xd1, 0x46, 0xbc, 0x69},
        .xLen   = 13,
    }
};
static const SeosCryptoApi_Key_Data dhPubData =
{
    .type = SeosCryptoApi_Key_TYPE_DH_PUB,
    .data.dh.pub = {
        .params = {
            .pBytes  = {0x12, 0xdf, 0x4d, 0x76, 0x89, 0xdf, 0xf4, 0xc9, 0x9d, 0x9a, 0xe5, 0x7d, 0x07},
            .pLen    = 13,
            .gBytes  = {0x00, 0x1e, 0x32, 0x15, 0x8a, 0x35, 0xe3, 0x4d, 0x7b, 0x61, 0x96, 0x57, 0xd6},
            .gLen    = 13,
        },
        .gxBytes = {0x00, 0x41, 0x83, 0xa8, 0x6f, 0x35, 0x71, 0x0e, 0x4e, 0x69, 0xb1, 0x64, 0xa4},
        .gxLen   = 13,
    }
};
static const unsigned char dhSharedResult[] =
{
    0x0a, 0x01, 0xa3, 0x91, 0x9f, 0x2b, 0xa3, 0x69, 0xdc, 0x5b, 0x11, 0xde, 0x2c
};

// From mbedtls test suite; only one curve supported right now
static const SeosCryptoApi_Key_Data ecPrvData =
{
    .type = SeosCryptoApi_Key_TYPE_SECP256R1_PRV,
    .data.secp256r1.prv = {
        .dBytes = {
            0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
            0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53
        },
        .dLen   = 32,
    }
};
static const SeosCryptoApi_Key_Data ecPubData =
{
    .type = SeosCryptoApi_Key_TYPE_SECP256R1_PUB,
    .data.secp256r1.pub = {
        .qxBytes = {
            0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87, 0xd0,
            0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11, 0x80
        },
        .qxLen   = 32,
        .qyBytes = {
            0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5, 0x9a,
            0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b, 0xb3
        },
        .qyLen   = 32,
    }
};
static const unsigned char ecdhSharedResult[] =
{
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde
};
static const SeosCryptoApi_Key_Spec dh64bSpec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_DH_PRV,
        .params.bits = 64
    }
};
static const SeosCryptoApi_Key_Spec secp256r1Spec =
{
    .type = SeosCryptoApi_Key_SPECTYPE_BITS,
    .key = {
        .attribs.flags = SeosCryptoApi_Key_FLAG_EXPORTABLE_RAW,
        .type = SeosCryptoApi_Key_TYPE_SECP256R1_PRV,
    }
};

static void
testAgreement_init_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;
    seos_err_t err;

    // Regular init with DH priv key
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_DH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Regular init with ECDH priv key
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_ECDH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_init_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key ecKey, dhKey;
    SeosCryptoApi_Agreement obj;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(api, &dhKey, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &ecKey, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without handle
    err = SeosCryptoApi_Agreement_init(api, NULL,
                                       SeosCryptoApi_Agreement_ALG_ECDH, &ecKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with invalid algorithm
    err = SeosCryptoApi_Agreement_init(api, &obj, 666, &ecKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Try with invalid key handle
    err = SeosCryptoApi_Agreement_init(api, &obj,
                                       SeosCryptoApi_Agreement_ALG_ECDH, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Try with DH public key
    err = SeosCryptoApi_Agreement_init(api, &obj,
                                       SeosCryptoApi_Agreement_ALG_DH, &dhKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with DH public key but ECDH alg
    err = SeosCryptoApi_Agreement_init(api, &obj,
                                       SeosCryptoApi_Agreement_ALG_ECDH, &dhKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with ECDH public key but DH alg
    err = SeosCryptoApi_Agreement_init(api, &obj,
                                       SeosCryptoApi_Agreement_ALG_DH, &ecKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with ECDH public key
    err = SeosCryptoApi_Agreement_init(api, &obj,
                                       SeosCryptoApi_Agreement_ALG_ECDH, &ecKey);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&ecKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&dhKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
agreeOnKey(
    SeosCryptoApi*     api,
    SeosCryptoApi_Key* prvKey,
    SeosCryptoApi_Key* pubKey,
    unsigned int       algo,
    unsigned char*     buf,
    size_t*            bufSize)
{
    SeosCryptoApi_Agreement obj;
    seos_err_t err;

    memset(buf, 0, *bufSize);

    // We have a prvKey key (and a pubKey one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    err = SeosCryptoApi_Agreement_init(api, &obj, algo, prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // We have received a pubKey key (e.g., from a server) and use this to derive a secret
    // key of a given length; for now, don't pass a RNG
    if ((err = SeosCryptoApi_Agreement_agree(&obj, pubKey, buf,
                                             bufSize)) != SEOS_SUCCESS)
    {
        return err;
    }

    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testAgreement_compute_DH_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(api, &pubKey, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    err = agreeOnKey(api, &prvKey, &pubKey, SeosCryptoApi_Agreement_ALG_DH,
                     clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, dhSharedResult,
                                  sizeof(dhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_DH_rnd_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key_Spec dh64pSpec =
    {
        .type = SeosCryptoApi_Key_SPECTYPE_PARAMS,
        .key = {
            .type = SeosCryptoApi_Key_TYPE_DH_PRV,
            // Params to be filled in later
        }
    };
    SeosCryptoApi_Key clPubKey, clPrvKey;
    SeosCryptoApi_Key svPubKey, svPrvKey;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_Key_generate(api, &svPrvKey, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(&svPubKey, &svPrvKey,
                                       &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Extract the public params and generate the client's keypair based on the
    // shared params
    n = sizeof(dh64pSpec.key.params);
    err = SeosCryptoApi_Key_getParams(&svPrvKey, &dh64pSpec.key.params, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sizeof(SeosCryptoApi_Key_DhParams) == n);
    err = SeosCryptoApi_Key_generate(api, &clPrvKey, &dh64pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(&clPubKey, &clPrvKey,
                                       &dh64pSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    err = agreeOnKey(api, &clPrvKey, &svPubKey, SeosCryptoApi_Agreement_ALG_DH,
                     clShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(svShared);
    err = agreeOnKey(api, &svPrvKey, &clPubKey, SeosCryptoApi_Agreement_ALG_DH,
                     svShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(&clPrvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&clPubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&svPrvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&svPubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(api, &pubKey, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    err = agreeOnKey(api, &prvKey, &pubKey, SeosCryptoApi_Agreement_ALG_ECDH,
                     clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, ecdhSharedResult,
                                  sizeof(ecdhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_rnd_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key clPubKey, clPrvKey;
    SeosCryptoApi_Key svPubKey, svPrvKey;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_Key_generate(api, &svPrvKey, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(&svPubKey, &svPrvKey,
                                       &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Genrate new keypair for client; the keytype specifies the params so no need
    // for them to be passed explcitly
    err = SeosCryptoApi_Key_generate(api, &clPrvKey, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(&clPubKey, &clPrvKey,
                                       &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    err = agreeOnKey(api, &clPrvKey, &svPubKey, SeosCryptoApi_Agreement_ALG_ECDH,
                     clShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(svShared);
    err = agreeOnKey(api, &svPrvKey, &clPubKey, SeosCryptoApi_Agreement_ALG_ECDH,
                     svShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(&clPrvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&clPubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&svPrvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&svPubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Agreement obj;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(api, &pubKey, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_ECDH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without agreement handle
    n = sizeof(clientShared);
    err = SeosCryptoApi_Agreement_agree(NULL, &pubKey, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with private key
    err = SeosCryptoApi_Agreement_agree(&obj, &prvKey, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with no key handle
    err = SeosCryptoApi_Agreement_agree(&obj, NULL, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Try without buffer
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try without giving size pointer
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, clientShared, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with too small buffer
    n = 17;
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_ok(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_DH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_fail(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_DH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty handle
    err = SeosCryptoApi_Agreement_free(NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_agree_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Agreement obj;
    static unsigned char sharedBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    seos_err_t err;
    size_t sharedLen;

    err = SeosCryptoApi_Key_import(api, &pubKey, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(api, &prvKey, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // We have a prvKey key (and a pubKey one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    err = SeosCryptoApi_Agreement_init(api, &obj, SeosCryptoApi_Agreement_ALG_DH,
                                       &prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should go through and get the resulting agreement size
    sharedLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf, &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sharedLen == dhPubData.data.dh.pub.params.pLen);

    // Should fail because it is too small but give minimum size
    sharedLen = 10;
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf, &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(sharedLen == dhPubData.data.dh.pub.params.pLen);

    // Should fail because output buffer is too big
    sharedLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf, &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(&obj);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&pubKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(&prvKey);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testAgreement(
    SeosCryptoApi* api)
{
    testAgreement_init_ok(api);
    testAgreement_init_fail(api);

    testAgreement_compute_DH_ok(api);
    testAgreement_compute_DH_rnd_ok(api);

    testAgreement_compute_ECDH_ok(api);
    testAgreement_compute_ECDH_rnd_ok(api);

    testAgreement_compute_fail(api);

    testAgreement_free_ok(api);
    testAgreement_free_fail(api);

    testAgreement_agree_buffer(api);
}