/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

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

static bool allowExport;
#define TEST_LOCATION(api, o) \
    Debug_ASSERT_OBJ_LOCATION(api, allowExport, o.agreement)

static void
test_SeosCryptoApi_Agreement_init_pos(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;

    TEST_START(api->mode, allowExport);

    // Regular init with DH priv key
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &dh101PrvData));
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_DH, &prvKey));
    TEST_LOCATION(api, obj);
    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    // Regular init with ECDH priv key
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &secp256r1PrvData));
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_ECDH, &prvKey));
    TEST_LOCATION(api, obj);
    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_init_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key ecKey, dhKey;
    SeosCryptoApi_Agreement obj;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &dhKey, &dh101PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &ecKey, &secp256r1PubData));

    // Try without handle
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_init(api, NULL,
                                                  SeosCryptoApi_Agreement_ALG_ECDH, &ecKey));

    // Try with invalid algorithm
    TEST_NOT_SUPP(SeosCryptoApi_Agreement_init(api, &obj, 666, &ecKey));

    // Try with invalid key handle
    TEST_INVAL_HANDLE(SeosCryptoApi_Agreement_init(api, &obj,
                                                   SeosCryptoApi_Agreement_ALG_ECDH, NULL));

    // Try with DH public key
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_init(api, &obj,
                                                  SeosCryptoApi_Agreement_ALG_DH, &dhKey));

    // Try with DH public key but ECDH alg
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_init(api, &obj,
                                                  SeosCryptoApi_Agreement_ALG_ECDH, &dhKey));

    // Try with ECDH public key but DH alg
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_init(api, &obj,
                                                  SeosCryptoApi_Agreement_ALG_DH, &ecKey));

    // Try with ECDH public key
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_init(api, &obj,
                                                  SeosCryptoApi_Agreement_ALG_ECDH, &ecKey));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&ecKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&dhKey));

    TEST_FINISH();
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
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj, algo, prvKey));
    TEST_LOCATION(api, obj);

    // We have received a pubKey key (e.g., from a server) and use this to derive a secret
    // key of a given length; for now, don't pass a RNG
    if ((err = SeosCryptoApi_Agreement_agree(&obj, pubKey, buf,
                                             bufSize)) != SEOS_SUCCESS)
    {
        return err;
    }

    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));

    return SEOS_SUCCESS;
}

static void
test_SeosCryptoApi_Agreement_do_DH(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &dh101PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &dh101PrvData));

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    TEST_SUCCESS(agreeOnKey(api, &prvKey, &pubKey, SeosCryptoApi_Agreement_ALG_DH,
                            clientShared, &n));
    // Make sure both actually match!
    TEST_TRUE(!memcmp(clientShared, dhSharedResult, sizeof(dhSharedResult)));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_do_DH_rnd(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key clPubKey, clPrvKey;
    SeosCryptoApi_Key svPubKey, svPrvKey;
    unsigned char clShared[64], svShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate a new keypair for the server
        TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &svPrvKey, &dh64bSpec));
        TEST_SUCCESS(SeosCryptoApi_Key_makePublic(&svPubKey, &svPrvKey,
                                                  &dh64bSpec.key.attribs));

        // Extract the public params and generate the client's keypair based on the
        // shared params
        n = sizeof(dh64pSpec.key.params);
        TEST_SUCCESS(SeosCryptoApi_Key_getParams(&svPrvKey, &dh64pSpec.key.params, &n));
        TEST_TRUE(sizeof(SeosCryptoApi_Key_DhParams) == n);
        TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &clPrvKey, &dh64pSpec));
        TEST_SUCCESS(SeosCryptoApi_Key_makePublic(&clPubKey, &clPrvKey,
                                                  &dh64pSpec.key.attribs));

        // Compute both sides of the key agreement and check if the match
        n = sizeof(clShared);
        TEST_SUCCESS(agreeOnKey(api, &clPrvKey, &svPubKey,
                                SeosCryptoApi_Agreement_ALG_DH, clShared, &n));
        n = sizeof(svShared);
        TEST_SUCCESS(agreeOnKey(api, &svPrvKey, &clPubKey,
                                SeosCryptoApi_Agreement_ALG_DH, svShared, &n));
        TEST_TRUE(!memcmp(clShared, svShared, n));

        TEST_SUCCESS(SeosCryptoApi_Key_free(&clPrvKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&clPubKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&svPrvKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&svPubKey));
    }

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_do_ECDH(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &secp256r1PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &secp256r1PrvData));

    // Compute the side of the CLIENT
    n = sizeof(clientShared);
    TEST_SUCCESS(agreeOnKey(api, &prvKey, &pubKey, SeosCryptoApi_Agreement_ALG_ECDH,
                            clientShared, &n));
    // Make sure both actually match!
    TEST_TRUE(!memcmp(clientShared, ecdhSharedResult, sizeof(ecdhSharedResult)));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_do_ECDH_rnd(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key clPubKey, clPrvKey;
    SeosCryptoApi_Key svPubKey, svPrvKey;
    unsigned char clShared[64], svShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    for (size_t i = 0; i < NUM_RAND_ITERATIONS; i++)
    {
        // Generate a new keypair for the server
        TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &svPrvKey, &secp256r1Spec));
        TEST_SUCCESS(SeosCryptoApi_Key_makePublic(&svPubKey, &svPrvKey,
                                                  &secp256r1Spec.key.attribs));

        // Genrate new keypair for client; the keytype specifies the params so no need
        // for them to be passed explcitly
        TEST_SUCCESS(SeosCryptoApi_Key_generate(api, &clPrvKey, &secp256r1Spec));
        TEST_SUCCESS(SeosCryptoApi_Key_makePublic(&clPubKey, &clPrvKey,
                                                  &secp256r1Spec.key.attribs));

        // Compute both sides of the key agreement and check if the match
        n = sizeof(clShared);
        TEST_SUCCESS(agreeOnKey(api, &clPrvKey, &svPubKey,
                                SeosCryptoApi_Agreement_ALG_ECDH, clShared, &n));
        n = sizeof(svShared);
        TEST_SUCCESS(agreeOnKey(api, &svPrvKey, &clPubKey,
                                SeosCryptoApi_Agreement_ALG_ECDH, svShared, &n));
        TEST_TRUE(!memcmp(clShared, svShared, n));

        TEST_SUCCESS(SeosCryptoApi_Key_free(&clPrvKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&clPubKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&svPrvKey));
        TEST_SUCCESS(SeosCryptoApi_Key_free(&svPubKey));
    }

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_agree_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Agreement obj;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &secp256r1PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &secp256r1PrvData));

    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_ECDH, &prvKey));
    TEST_LOCATION(api, obj);

    // Try without agreement handle
    n = sizeof(clientShared);
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_agree(NULL, &pubKey, clientShared,
                                                   &n));

    // Try with private key
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_agree(&obj, &prvKey, clientShared,
                                                   &n));

    // Try with no key handle
    TEST_INVAL_HANDLE(SeosCryptoApi_Agreement_agree(&obj, NULL, clientShared, &n));

    // Try without buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_agree(&obj, &pubKey, NULL, &n));

    // Try without giving size pointer
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_agree(&obj, &pubKey, clientShared,
                                                   NULL));

    // Try with too small buffer
    n = 17;
    TEST_TOO_SMALL(SeosCryptoApi_Agreement_agree(&obj, &pubKey, clientShared, &n));

    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_free_pos(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &dh101PrvData));
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_DH, &prvKey));
    TEST_LOCATION(api, obj);
    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_free_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key prvKey;
    SeosCryptoApi_Agreement obj;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &dh101PrvData));
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_DH, &prvKey));
    TEST_LOCATION(api, obj);

    // Empty handle
    TEST_INVAL_PARAM(SeosCryptoApi_Agreement_free(NULL));

    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_agree_buffer(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    SeosCryptoApi_Agreement obj;
    static unsigned char sharedBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t sharedLen;

    TEST_START(api->mode, allowExport);

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &dh101PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &dh101PrvData));

    // We have a prvKey key (and a pubKey one) and want to use to to agree on a shared
    // secret to perform symmetric cryptography
    TEST_SUCCESS(SeosCryptoApi_Agreement_init(api, &obj,
                                              SeosCryptoApi_Agreement_ALG_DH, &prvKey));
    TEST_LOCATION(api, obj);

    // Should go through and get the resulting agreement size
    sharedLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_SUCCESS(SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf,
                                               &sharedLen));
    TEST_TRUE(sharedLen == dh101PubData.data.dh.pub.params.pLen);

    // Should fail because it is too small but give minimum size
    sharedLen = 10;
    TEST_TOO_SMALL(SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf,
                                                 &sharedLen));
    TEST_TRUE(sharedLen == dh101PubData.data.dh.pub.params.pLen);

    // Should fail because output buffer is too big
    sharedLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Agreement_agree(&obj, &pubKey, sharedBuf,
                                                    &sharedLen));

    TEST_SUCCESS(SeosCryptoApi_Agreement_free(&obj));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Agreement_key_neg(
    SeosCryptoApi* api)
{
    SeosCryptoApi_Key pubKey, prvKey;
    unsigned char clientShared[64];
    size_t n;

    TEST_START(api->mode, allowExport);

    // Test with both keys having different exportable attributes
    secp256r1PrvData.attribs.exportable = false;
    secp256r1PubData.attribs.exportable = true;

    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &pubKey, &secp256r1PubData));
    TEST_SUCCESS(SeosCryptoApi_Key_import(api, &prvKey, &secp256r1PrvData));

    // Should fail, because objects are in different locations
    n = sizeof(clientShared);
    TEST_INVAL_HANDLE(agreeOnKey(api, &prvKey, &pubKey,
                                 SeosCryptoApi_Agreement_ALG_ECDH,
                                 clientShared, &n));

    TEST_SUCCESS(SeosCryptoApi_Key_free(&pubKey));
    TEST_SUCCESS(SeosCryptoApi_Key_free(&prvKey));

    TEST_FINISH();
}

void
test_SeosCryptoApi_Agreement(
    SeosCryptoApi* api)
{
    allowExport = true;
    keyData_setExportable(keyDataList, allowExport);
    keySpec_setExportable(keySpecList, allowExport);

    test_SeosCryptoApi_Agreement_init_pos(api);
    test_SeosCryptoApi_Agreement_init_neg(api);

    test_SeosCryptoApi_Agreement_agree_neg(api);

    test_SeosCryptoApi_Agreement_free_pos(api);
    test_SeosCryptoApi_Agreement_free_neg(api);

    test_SeosCryptoApi_Agreement_agree_buffer(api);

    // Test vectors
    test_SeosCryptoApi_Agreement_do_DH(api);
    test_SeosCryptoApi_Agreement_do_ECDH(api);

    // Test with randomly generated values for multiple iterations
    test_SeosCryptoApi_Agreement_do_DH_rnd(api);
    test_SeosCryptoApi_Agreement_do_ECDH_rnd(api);

    // Make all used keys NON-EXPORTABLE and re-run parts of the tests
    if (api->mode == SeosCryptoApi_Mode_ROUTER)
    {
        allowExport = false;
        keyData_setExportable(keyDataList, allowExport);
        keySpec_setExportable(keySpecList, allowExport);

        test_SeosCryptoApi_Agreement_do_DH(api);
        test_SeosCryptoApi_Agreement_do_DH_rnd(api);

        test_SeosCryptoApi_Agreement_do_ECDH(api);
        test_SeosCryptoApi_Agreement_do_ECDH_rnd(api);

        test_SeosCryptoApi_Agreement_key_neg(api);
    }
}