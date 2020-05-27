/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "ObjectLocation.h"
#include "SharedKeys.h"
#include "TestMacros.h"

#include <string.h>

// From mbedtls test suite; has very small keylength, do not use for anything
// other than testing!!
static const unsigned char dhSharedResult[] =
{
    0x0a, 0x01, 0xa3, 0x91, 0x9f, 0x2b, 0xa3, 0x69, 0xdc, 0x5b, 0x11, 0xde, 0x2c
};
static const unsigned char ecdhSharedResult[] =
{
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde
};

#define NUM_RAND_ITERATIONS 5

static void
test_OS_CryptoAgreement_init_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPrvKey;
    OS_CryptoAgreement_Handle_t hAgree;

    TEST_START(mode, expo);

    // Regular init with DH priv key
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &dh101PrvData));
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_DH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);
    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    // Regular init with ECDH priv key
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &secp256r1PrvData));
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_ECDH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);
    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_init_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hEcKey, hDhKey;
    OS_CryptoAgreement_Handle_t hAgree;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hDhKey, hCrypto, &dh101PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hEcKey, hCrypto, &secp256r1PubData));

    // Try without agreement handle
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(NULL, hCrypto, hEcKey,
                                             OS_CryptoAgreement_ALG_ECDH));

    // Try without crypto handle
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(&hAgree, NULL, hEcKey,
                                             OS_CryptoAgreement_ALG_ECDH));

    // Try with invalid key handle
    TEST_INVAL_HANDLE(OS_CryptoAgreement_init(&hAgree, hCrypto, NULL,
                                              OS_CryptoAgreement_ALG_ECDH));

    // Try with invalid algorithm
    TEST_NOT_SUPP(OS_CryptoAgreement_init(&hAgree, hCrypto, hEcKey, 666));

    // Try with DH public key
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(&hAgree, hCrypto, hDhKey,
                                             OS_CryptoAgreement_ALG_DH));

    // Try with DH public key but ECDH alg
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(&hAgree, hCrypto, hDhKey,
                                             OS_CryptoAgreement_ALG_ECDH));

    // Try with ECDH public key but DH alg
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(&hAgree, hCrypto, hEcKey,
                                             OS_CryptoAgreement_ALG_DH));

    // Try with ECDH public key
    TEST_INVAL_PARAM(OS_CryptoAgreement_init(&hAgree, hCrypto, hEcKey,
                                             OS_CryptoAgreement_ALG_ECDH));

    TEST_SUCCESS(OS_CryptoKey_free(hEcKey));
    TEST_SUCCESS(OS_CryptoKey_free(hDhKey));

    TEST_FINISH();
}

static OS_Error_t
agreeOnKey(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo,
    OS_CryptoKey_Handle_t  hPrvKey,
    OS_CryptoKey_Handle_t  hPubKey,
    unsigned int           algo,
    unsigned char*         buf,
    size_t*                bufSize)
{
    OS_CryptoAgreement_Handle_t hAgree;
    OS_Error_t err;

    memset(buf, 0, *bufSize);

    // We have a hPrvKey key (and a hPubKey one) and want to use it to agree on a
    // shared secret to perform symmetric cryptography
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey, algo));
    TEST_LOCACTION_EXP(mode, expo, hAgree);

    // We have received a hPubKey key (e.g., from a server) and use this to derive a secret
    // key of a given length; for now, don't pass a RNG
    if ((err = OS_CryptoAgreement_agree(hAgree, hPubKey, buf,
                                        bufSize)) != OS_SUCCESS)
    {
        return err;
    }

    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));

    return OS_SUCCESS;
}

static void
test_OS_CryptoAgreement_do_DH(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPubKey, hPrvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &dh101PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &dh101PrvData));

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo,
                            hPrvKey, hPubKey,
                            OS_CryptoAgreement_ALG_DH,
                            clientShared, &n));
    // Make sure both actually match!
    TEST_TRUE(!memcmp(clientShared, dhSharedResult, sizeof(dhSharedResult)));

    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_do_DH_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hCliPubKey, hCliPrvKey;
    OS_CryptoKey_Handle_t hSvrPubKey, hSvrPrvKey;
    unsigned char clShared[64], svShared[64];
    size_t n;

    TEST_START(mode, expo);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate a new keypair for the server
        TEST_SUCCESS(OS_CryptoKey_generate(&hSvrPrvKey, hCrypto, &dh64bSpec));
        TEST_SUCCESS(OS_CryptoKey_makePublic(&hSvrPubKey, hCrypto, hSvrPrvKey,
                                             &dh64bSpec.key.attribs));

        // Extract the public params and generate the client's keypair based on the
        // shared params
        n = sizeof(dh64pSpec.key.params);
        TEST_SUCCESS(OS_CryptoKey_getParams(hSvrPrvKey, &dh64pSpec.key.params,
                                            &n));
        TEST_TRUE(sizeof(OS_CryptoKey_DhParams_t) == n);
        TEST_SUCCESS(OS_CryptoKey_generate(&hCliPrvKey, hCrypto, &dh64pSpec));
        TEST_SUCCESS(OS_CryptoKey_makePublic(&hCliPubKey, hCrypto, hCliPrvKey,
                                             &dh64pSpec.key.attribs));

        // Compute both sides of the key agreement and check if the match
        n = sizeof(clShared);
        TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo,
                                hCliPrvKey, hSvrPubKey,
                                OS_CryptoAgreement_ALG_DH, clShared, &n));
        n = sizeof(svShared);
        TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo,
                                hSvrPrvKey, hCliPubKey,
                                OS_CryptoAgreement_ALG_DH, svShared, &n));
        TEST_TRUE(!memcmp(clShared, svShared, n));

        TEST_SUCCESS(OS_CryptoKey_free(hCliPrvKey));
        TEST_SUCCESS(OS_CryptoKey_free(hCliPubKey));
        TEST_SUCCESS(OS_CryptoKey_free(hSvrPrvKey));
        TEST_SUCCESS(OS_CryptoKey_free(hSvrPubKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_do_ECDH(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPubKey, hPrvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &secp256r1PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &secp256r1PrvData));

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo,
                            hPrvKey, hPubKey,
                            OS_CryptoAgreement_ALG_ECDH,
                            clientShared, &n));
    // Make sure both actually match!
    TEST_TRUE(!memcmp(clientShared, ecdhSharedResult, sizeof(ecdhSharedResult)));

    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_do_ECDH_rnd(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hCliPubKey, hCliPrvKey;
    OS_CryptoKey_Handle_t hSvrPubKey, hSvrPrvKey;
    unsigned char clShared[64], svShared[64];
    size_t n;

    TEST_START(mode, expo);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate a new keypair for the server
        TEST_SUCCESS(OS_CryptoKey_generate(&hSvrPrvKey, hCrypto, &secp256r1Spec));
        TEST_SUCCESS(OS_CryptoKey_makePublic(&hSvrPubKey, hCrypto, hSvrPrvKey,
                                             &secp256r1Spec.key.attribs));

        // Genrate new keypair for client; the keytype specifies the params so no need
        // for them to be passed explcitly
        TEST_SUCCESS(OS_CryptoKey_generate(&hCliPrvKey, hCrypto, &secp256r1Spec));
        TEST_SUCCESS(OS_CryptoKey_makePublic(&hCliPubKey, hCrypto, hCliPrvKey,
                                             &secp256r1Spec.key.attribs));

        // Compute both sides of the key agreement and check if the match
        n = sizeof(clShared);
        TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo,
                                hCliPrvKey, hSvrPubKey,
                                OS_CryptoAgreement_ALG_ECDH, clShared, &n));
        n = sizeof(svShared);
        TEST_SUCCESS(agreeOnKey(hCrypto,  mode, expo, hSvrPrvKey, hCliPubKey,
                                OS_CryptoAgreement_ALG_ECDH, svShared, &n));
        TEST_TRUE(!memcmp(clShared, svShared, n));

        TEST_SUCCESS(OS_CryptoKey_free(hCliPrvKey));
        TEST_SUCCESS(OS_CryptoKey_free(hCliPubKey));
        TEST_SUCCESS(OS_CryptoKey_free(hSvrPrvKey));
        TEST_SUCCESS(OS_CryptoKey_free(hSvrPubKey));
    }

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_agree_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPubKey, hPrvKey;
    OS_CryptoAgreement_Handle_t hAgree;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &secp256r1PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &secp256r1PrvData));

    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_ECDH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);

    // Try without agreement handle
    n = sizeof(clientShared);
    TEST_INVAL_PARAM(OS_CryptoAgreement_agree(NULL, hPubKey, clientShared,
                                              &n));

    // Try with private key
    TEST_INVAL_PARAM(OS_CryptoAgreement_agree(hAgree, hPrvKey, clientShared,
                                              &n));

    // Try with no key handle
    TEST_INVAL_HANDLE(OS_CryptoAgreement_agree(hAgree, NULL, clientShared,
                                               &n));

    // Try without buffer
    TEST_INVAL_PARAM(OS_CryptoAgreement_agree(hAgree, hPubKey, NULL, &n));

    // Try without giving size pointer
    TEST_INVAL_PARAM(OS_CryptoAgreement_agree(hAgree, hPubKey, clientShared,
                                              NULL));

    // Try with too small buffer
    n = 17;
    TEST_TOO_SMALL(OS_CryptoAgreement_agree(hAgree, hPubKey, clientShared,
                                            &n));

    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));

    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_free_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPrvKey;
    OS_CryptoAgreement_Handle_t hAgree;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &dh101PrvData));
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_DH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);
    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_free_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPrvKey;
    OS_CryptoAgreement_Handle_t hAgree;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &dh101PrvData));
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_DH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);

    // Empty handle
    TEST_INVAL_PARAM(OS_CryptoAgreement_free(NULL));

    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_agree_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPubKey, hPrvKey;
    OS_CryptoAgreement_Handle_t hAgree;
    static unsigned char sharedBuf[OS_Crypto_SIZE_DATAPORT + 1];
    size_t sharedLen;

    TEST_START(mode, expo);

    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &dh101PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &dh101PrvData));

    // We have a hPrvKey key (and a hPubKey one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    TEST_SUCCESS(OS_CryptoAgreement_init(&hAgree, hCrypto, hPrvKey,
                                         OS_CryptoAgreement_ALG_DH));
    TEST_LOCACTION_EXP(mode, expo, hAgree);

    // Should go through and get the resulting agreement size
    sharedLen = OS_Crypto_SIZE_DATAPORT;
    TEST_SUCCESS(OS_CryptoAgreement_agree(hAgree, hPubKey, sharedBuf,
                                          &sharedLen));
    TEST_TRUE(sharedLen == dh101PubData.data.dh.pub.params.pLen);

    // Should fail because it is too small but give minimum size
    sharedLen = 10;
    TEST_TOO_SMALL(OS_CryptoAgreement_agree(hAgree, hPubKey, sharedBuf,
                                            &sharedLen));
    TEST_TRUE(sharedLen == dh101PubData.data.dh.pub.params.pLen);

    // Should fail because output buffer is too big
    sharedLen = OS_Crypto_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(OS_CryptoAgreement_agree(hAgree, hPubKey, sharedBuf,
                                               &sharedLen));

    TEST_SUCCESS(OS_CryptoAgreement_free(hAgree));
    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

static void
test_OS_CryptoAgreement_key_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode,
    const bool             expo)
{
    OS_CryptoKey_Handle_t hPubKey, hPrvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(mode, expo);

    // Test with both keys having different exportable attributes
    secp256r1PrvData.attribs.exportable = false;
    secp256r1PubData.attribs.exportable = true;

    TEST_SUCCESS(OS_CryptoKey_import(&hPubKey, hCrypto, &secp256r1PubData));
    TEST_SUCCESS(OS_CryptoKey_import(&hPrvKey, hCrypto, &secp256r1PrvData));

    // Should fail, because objects are in different locations
    n = sizeof(clientShared);
    TEST_INVAL_HANDLE(agreeOnKey(hCrypto, mode, expo,
                                 hPrvKey, hPubKey,
                                 OS_CryptoAgreement_ALG_ECDH,
                                 clientShared, &n));

    TEST_SUCCESS(OS_CryptoKey_free(hPubKey));
    TEST_SUCCESS(OS_CryptoKey_free(hPrvKey));

    TEST_FINISH();
}

void
test_OS_CryptoAgreement(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    bool expo = true;

    keyData_setExportable(keyDataList, expo);
    keySpec_setExportable(keySpecList, expo);

    test_OS_CryptoAgreement_init_pos(hCrypto, mode, expo);
    test_OS_CryptoAgreement_init_neg(hCrypto, mode, expo);

    test_OS_CryptoAgreement_agree_neg(hCrypto, mode, expo);

    test_OS_CryptoAgreement_free_pos(hCrypto, mode, expo);
    test_OS_CryptoAgreement_free_neg(hCrypto, mode, expo);

    test_OS_CryptoAgreement_agree_buffer(hCrypto, mode, expo);

    // Test vectors
    test_OS_CryptoAgreement_do_DH(hCrypto, mode, expo);
    test_OS_CryptoAgreement_do_ECDH(hCrypto, mode, expo);

    // Test with randomly generated values for multiple iterations
    test_OS_CryptoAgreement_do_DH_rnd(hCrypto, mode, expo);
    test_OS_CryptoAgreement_do_ECDH_rnd(hCrypto, mode, expo);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (mode == OS_Crypto_MODE_CLIENT)
    {
        expo = false;

        keyData_setExportable(keyDataList, expo);
        keySpec_setExportable(keySpecList, expo);

        test_OS_CryptoAgreement_do_DH(hCrypto, mode, expo);
        test_OS_CryptoAgreement_do_DH_rnd(hCrypto, mode, expo);

        test_OS_CryptoAgreement_do_ECDH(hCrypto, mode, expo);
        test_OS_CryptoAgreement_do_ECDH_rnd(hCrypto, mode, expo);

        test_OS_CryptoAgreement_key_neg(hCrypto, mode, expo);
    }
}
