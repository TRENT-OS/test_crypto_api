/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosCryptoAgreement.h"
#include "SeosCryptoApi.h"

#include <string.h>

// From mbedtls test suite; has very small keylength, do not use for anything
// other than testing!!
static const SeosCryptoKey_Data dhPrvData =
{
    .type = SeosCryptoKey_Type_DH_PRV,
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
static const SeosCryptoKey_Data dhPubData =
{
    .type = SeosCryptoKey_Type_DH_PUB,
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
static const SeosCryptoKey_Data ecPrvData =
{
    .type = SeosCryptoKey_Type_SECP256R1_PRV,
    .data.secp256r1.prv = {
        .dBytes = {
            0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97, 0xce, 0x20,
            0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46, 0x47, 0x6b, 0xee, 0x53
        },
        .dLen   = 32,
    }
};
static const SeosCryptoKey_Data ecPubData =
{
    .type = SeosCryptoKey_Type_SECP256R1_PUB,
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
static const SeosCryptoKey_Spec dh64bSpec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .type = SeosCryptoKey_Type_DH_PRV,
        .params.bits = 64
    }
};
static const SeosCryptoKey_Spec secp256r1Spec =
{
    .type = SeosCryptoKey_SpecType_BITS,
    .key = {
        .attribs.flags = SeosCryptoKey_Flags_EXPORTABLE_RAW,
        .type = SeosCryptoKey_Type_SECP256R1_PRV,
    }
};

static void
testAgreement_init_ok(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle prvHandle = NULL;
    SeosCrypto_AgreementHandle agrHandle = NULL;
    seos_err_t err;

    // Regular init with DH priv key
    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_agreementFree(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Regular init with ECDH priv key
    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_ECDH, prvHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_agreementFree(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_init_fail(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle ecHandle = NULL, dhHandle = NULL;
    SeosCrypto_AgreementHandle agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_keyImport(ctx, &dhHandle, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &ecHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without handle
    err = SeosCryptoApi_agreementInit(ctx, NULL,
                                      SeosCryptoAgreement_Algorithm_ECDH, ecHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);
  
    // Try with invalid algorithm
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle, 666, ecHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_NOT_SUPPORTED, "err %d", err);
   
    // Try with invalid key handle
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_ECDH, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_HANDLE, "err %d", err);

    // Try with DH public key
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_DH, dhHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);
  
    // Try with DH public key but ECDH alg
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_ECDH, dhHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);
    
    // Try with ECDH public key but DH alg
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_DH, ecHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);
   
    // Try with ECDH public key
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_ECDH, ecHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, ecHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, dhHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
agreeOnKey(SeosCryptoCtx*       ctx,
           SeosCrypto_KeyHandle prvHandle,
           SeosCrypto_KeyHandle pubHandle,
           unsigned int         algo,
           unsigned char*       buf,
           size_t*              bufSize)
{
    SeosCrypto_AgreementHandle agrHandle = NULL;
    seos_err_t err;

    memset(buf, 0, *bufSize);

    // We have a prvHandle key (and a pubHandle one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle, algo, prvHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    // We have received a pubHandle key (e.g., from a server) and use this to derive a secret
    // key of a given length; for now, don't pass a RNG
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, pubHandle, buf,
                                       bufSize);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    SeosCryptoApi_agreementFree(ctx, agrHandle);
}

static void
testAgreement_compute_DH_ok(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle pubHandle = NULL, prvHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_keyImport(ctx, &pubHandle, NULL, &dhPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    agreeOnKey(ctx, prvHandle, pubHandle, SeosCryptoAgreement_Algorithm_DH,
               clientShared, &n);
    // // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, dhSharedResult,
                                  sizeof(dhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_keyFree(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_DH_rnd_ok(SeosCryptoCtx* ctx)
{
    SeosCryptoKey_Spec dh64pSpec =
    {
        .type = SeosCryptoKey_SpecType_PARAMS,
        .key = {
            .type = SeosCryptoKey_Type_DH_PRV,
            // Params to be filled in later
        }
    };
    SeosCrypto_KeyHandle clPubHandle = NULL, clPrvHandle = NULL;
    SeosCrypto_KeyHandle svPubHandle = NULL, svPrvHandle = NULL;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_keyGenerate(ctx, &svPrvHandle, &dh64bSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyMakePublic(ctx, &svPubHandle, svPrvHandle,
                                         &dh64bSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Extract the public params and generate the client's keypair based on the
    // shared params
    n = sizeof(dh64pSpec.key.params);
    err = SeosCryptoApi_keyGetParams(ctx, svPrvHandle, &dh64pSpec.key.params,
                                        &n);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    Debug_ASSERT(sizeof(SeosCryptoKey_DHParams) == n);
    err = SeosCryptoApi_keyGenerate(ctx, &clPrvHandle, &dh64pSpec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyMakePublic(ctx, &clPubHandle, clPrvHandle,
                                         &dh64pSpec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    agreeOnKey(ctx, clPrvHandle, svPubHandle, SeosCryptoAgreement_Algorithm_DH,
               clShared, &n);
    n = sizeof(svShared);
    agreeOnKey(ctx, svPrvHandle, clPubHandle, SeosCryptoAgreement_Algorithm_DH,
               svShared, &n);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_keyFree(ctx, clPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, clPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, svPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, svPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_ok(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle pubHandle = NULL, prvHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_keyImport(ctx, &pubHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    agreeOnKey(ctx, prvHandle, pubHandle, SeosCryptoAgreement_Algorithm_ECDH,
               clientShared, &n);
    // Make sure both actually match!
    Debug_ASSERT_PRINTFLN(!memcmp(clientShared, ecdhSharedResult,
                                  sizeof(ecdhSharedResult)), "Shared key mismatch");

    err = SeosCryptoApi_keyFree(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_ECDH_rnd_ok(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle clPubHandle = NULL, clPrvHandle = NULL;
    SeosCrypto_KeyHandle svPubHandle = NULL, svPrvHandle = NULL;
    unsigned char clShared[64], svShared[64];
    seos_err_t err;
    size_t n;

    // Generate a new keypair for the server
    err = SeosCryptoApi_keyGenerate(ctx, &svPrvHandle, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyMakePublic(ctx, &svPubHandle, svPrvHandle,
                                         &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Genrate new keypair for client; the keytype specifies the params so no need
    // for them to be passed explcitly
    err = SeosCryptoApi_keyGenerate(ctx, &clPrvHandle, &secp256r1Spec);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyMakePublic(ctx, &clPubHandle, clPrvHandle,
                                         &secp256r1Spec.key.attribs);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Compute both sides of the key agreement and check if the match
    n = sizeof(clShared);
    agreeOnKey(ctx, clPrvHandle, svPubHandle, SeosCryptoAgreement_Algorithm_ECDH,
               clShared, &n);
    n = sizeof(svShared);
    agreeOnKey(ctx, svPrvHandle, clPubHandle, SeosCryptoAgreement_Algorithm_ECDH,
               svShared, &n);
    Debug_ASSERT_PRINTFLN(!memcmp(clShared, svShared, n), "Shared key mismatch");

    err = SeosCryptoApi_keyFree(ctx, clPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, clPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, svPrvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, svPubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_compute_fail(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle pubHandle = NULL, prvHandle = NULL;
    SeosCrypto_AgreementHandle agrHandle = NULL;
    unsigned char clientShared[64];
    seos_err_t err;
    size_t n;

    err = SeosCryptoApi_keyImport(ctx, &pubHandle, NULL, &ecPubData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &ecPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_ECDH, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    // Try without context
    n = sizeof(clientShared);
    err = SeosCryptoApi_agreementAgree(NULL, agrHandle, prvHandle, clientShared,
                                       &n);

    // Try without agreement handle
    err = SeosCryptoApi_agreementAgree(ctx, NULL, prvHandle, clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);
 
    // Try with private key
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, prvHandle,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER  == err, "err %d", err);
 
    // Try with no key handle
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, NULL,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_HANDLE == err, "err %d", err);
  
    // Try without buffer
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, pubHandle,
                                       NULL, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);
 
    // Try without giving size pointer
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, pubHandle,
                                       clientShared, NULL);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Try with too small buffer
    n = 17;
    err = SeosCryptoApi_agreementAgree(ctx, agrHandle, pubHandle,
                                       clientShared, &n);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_BUFFER_TOO_SMALL == err, "err %d", err);

    err = SeosCryptoApi_agreementFree(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    err = SeosCryptoApi_keyFree(ctx, pubHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_ok(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle prvHandle = NULL;
    SeosCrypto_AgreementHandle agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_agreementFree(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

static void
testAgreement_free_fail(SeosCryptoCtx* ctx)
{
    SeosCrypto_KeyHandle prvHandle = NULL;
    SeosCrypto_AgreementHandle agrHandle = NULL;
    seos_err_t err;

    err = SeosCryptoApi_keyImport(ctx, &prvHandle, NULL, &dhPrvData);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);
    err = SeosCryptoApi_agreementInit(ctx, &agrHandle,
                                      SeosCryptoAgreement_Algorithm_DH, prvHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    // Empty ctx
    err = SeosCryptoApi_agreementFree(NULL, agrHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_PARAMETER, "err %d", err);

    // Empty handle
    err = SeosCryptoApi_agreementFree(ctx, NULL);
    Debug_ASSERT_PRINTFLN(err == SEOS_ERROR_INVALID_HANDLE, "err %d", err);

    err = SeosCryptoApi_agreementFree(ctx, agrHandle);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_keyFree(ctx, prvHandle);
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    Debug_PRINTF("->%s: OK\n", __func__);
}

void
testAgreement(SeosCryptoCtx* ctx)
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
}