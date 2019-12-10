/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
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
testAgreement_init_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    seos_err_t err;

    // Regular init with DH priv key
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Regular init with ECDH priv key
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_ECDH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_init_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key ecHandle = NULL, dhHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(ctx, &dhHandle, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &ecHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without handle
    err = SeosCryptoApi_Agreement_init(ctx, NULL,
                                      SeosCryptoApi_Agreement_ALG_ECDH, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with invalid algorithm
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle, 666, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Try with invalid key handle
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_ECDH, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Try with DH public key
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, dhHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with DH public key but ECDH alg
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_ECDH, dhHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with ECDH public key but DH alg
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with ECDH public key
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_ECDH, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Key_free(ctx, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, dhHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static seos_err_t
agreeOnKey(SeosCryptoApi_Context* ctx,
           SeosCryptoApi_Key      prvHandle,
           SeosCryptoApi_Key      pubHandle,
           unsigned int           algo,
           unsigned char*         buf,
           size_t*                bufSize)
{
    SeosCryptoApi_Agreement agrHandle = NULL;
    seos_err_t err;

    memset(buf, 0, *bufSize);

    // We have a prvHandle key (and a pubHandle one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle, algo, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // We have received a pubHandle key (e.g., from a server) and use this to derive a secret
    // key of a given length; for now, don't pass a RNG
    if ((err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle, buf,
                                            bufSize)) != SEOS_SUCCESS)
    {
        return err;
    }

    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    return SEOS_SUCCESS;
}

static void
testAgreement_compute_DH_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubHandle = NULL, prvHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(ctx, &pubHandle, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    err = agreeOnKey(ctx, prvHandle, pubHandle, SeosCryptoApi_Agreement_ALG_DH,
                     clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, dhSharedResult,
                                  sizeof(dhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_DH_rnd_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key_Spec dh64pSpec =
    {
        .type = SeosCryptoApi_Key_SPECTYPE_PARAMS,
        .key = {
            .type = SeosCryptoApi_Key_TYPE_DH_PRV,
            // Params to be filled in later
        }
    };
    SeosCryptoApi_Key clPubHandle = NULL, clPrvHandle = NULL;
    SeosCryptoApi_Key svPubHandle = NULL, svPrvHandle = NULL;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_Key_generate(ctx, &svPrvHandle, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(ctx, &svPubHandle, svPrvHandle,
                                      &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Extract the public params and generate the client's keypair based on the
    // shared params
    n = sizeof(dh64pSpec.key.params);
    err = SeosCryptoApi_Key_getParams(ctx, svPrvHandle, &dh64pSpec.key.params,
                                     &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sizeof(SeosCryptoApi_Key_DhParams) == n);
    err = SeosCryptoApi_Key_generate(ctx, &clPrvHandle, &dh64pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(ctx, &clPubHandle, clPrvHandle,
                                      &dh64pSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    err = agreeOnKey(ctx, clPrvHandle, svPubHandle,
                     SeosCryptoApi_Agreement_ALG_DH,
                     clShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(svShared);
    err = agreeOnKey(ctx, svPrvHandle, clPubHandle,
                     SeosCryptoApi_Agreement_ALG_DH,
                     svShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(ctx, clPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, clPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, svPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, svPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubHandle = NULL, prvHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(ctx, &pubHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    err = agreeOnKey(ctx, prvHandle, pubHandle, SeosCryptoApi_Agreement_ALG_ECDH,
                     clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, ecdhSharedResult,
                                  sizeof(ecdhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_rnd_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key clPubHandle = NULL, clPrvHandle = NULL;
    SeosCryptoApi_Key svPubHandle = NULL, svPrvHandle = NULL;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_Key_generate(ctx, &svPrvHandle, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(ctx, &svPubHandle, svPrvHandle,
                                      &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Genrate new keypair for client; the keytype specifies the params so no need
    // for them to be passed explcitly
    err = SeosCryptoApi_Key_generate(ctx, &clPrvHandle, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_makePublic(ctx, &clPubHandle, clPrvHandle,
                                      &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    err = agreeOnKey(ctx, clPrvHandle, svPubHandle,
                     SeosCryptoApi_Agreement_ALG_ECDH,
                     clShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    n = sizeof(svShared);
    err = agreeOnKey(ctx, svPrvHandle, clPubHandle,
                     SeosCryptoApi_Agreement_ALG_ECDH,
                     svShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_Key_free(ctx, clPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, clPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, svPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, svPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubHandle = NULL, prvHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_Key_import(ctx, &pubHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_ECDH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without context
    n = sizeof(clientShared);
    err = SeosCryptoApi_Agreement_agree(NULL, agrHandle, prvHandle, clientShared,
                                       &n);

    // Try without agreement handle
    err = SeosCryptoApi_Agreement_agree(ctx, NULL, prvHandle, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Try with private key
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, prvHandle,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER  == err, "err %d", err);

    // Try with no key handle
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, NULL,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    // Try without buffer
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle,
                                       NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try without giving size pointer
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle,
                                       clientShared, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with too small buffer
    n = 17;
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_Key_free(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_ok(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_fail(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key prvHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Empty ctx
    err = SeosCryptoApi_Agreement_free(NULL, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Empty handle
    err = SeosCryptoApi_Agreement_free(ctx, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_agree_buffer(SeosCryptoApi_Context* ctx)
{
    SeosCryptoApi_Key pubHandle = NULL, prvHandle = NULL;
    SeosCryptoApi_Agreement agrHandle = NULL;
    static unsigned char sharedBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    seos_err_t err;
    size_t sharedLen;

    err = SeosCryptoApi_Key_import(ctx, &pubHandle, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_import(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // We have a prvHandle key (and a pubHandle one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    err = SeosCryptoApi_Agreement_init(ctx, &agrHandle,
                                      SeosCryptoApi_Agreement_ALG_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Should go through and get the resulting agreement size
    sharedLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle, sharedBuf,
                                       &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sharedLen == dhPubData.data.dh.pub.params.pLen);

    // Should fail because it is too small but give minimum size
    sharedLen = 10;
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle, sharedBuf,
                                       &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);
    Debug_ASSERT(sharedLen == dhPubData.data.dh.pub.params.pLen);

    // Should fail because output buffer is too big
    sharedLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Agreement_agree(ctx, agrHandle, pubHandle, sharedBuf,
                                       &sharedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    err = SeosCryptoApi_Agreement_free(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_Key_free(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testAgreement(SeosCryptoApi_Context* ctx)
{
    testAgreement_init_ok(ctx);
    testAgreement_init_fail(ctx);

    testAgreement_compute_DH_ok(ctx);
    testAgreement_compute_DH_rnd_ok(ctx);

    testAgreement_compute_ECDH_ok(ctx);
    testAgreement_compute_ECDH_rnd_ok(ctx);

    testAgreement_compute_fail(ctx);

    testAgreement_free_ok(ctx);
    testAgreement_free_fail(ctx);

    testAgreement_agree_buffer(ctx);
}