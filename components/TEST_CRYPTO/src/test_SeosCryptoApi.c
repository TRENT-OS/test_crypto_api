/**
 * @addtogroup CryptoApi_Tests
 * @{
 *
 * @file testRunner.c
 *
 * @brief top level test for the crypto API and the key store API
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "TestMacros.h"

#include <camkes.h>
#include <string.h>

// These are the tests for the sub-modules of the API
void test_SeosCryptoApi_Agreement(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Cipher(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Digest(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Key(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Mac(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Rng(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);
void test_SeosCryptoApi_Signature(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode);

// Forward declaration
static int entropy(
    void*, unsigned char*, size_t);

// These are all the configurations of the Crypto API we want to test
static SeosCryptoApi_Config cfgLib =
{
    .mode = SeosCryptoApi_Mode_LIBRARY,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
    .impl.lib.rng.entropy = entropy,
};
static SeosCryptoApi_Config cfgClient =
{
    .mode = SeosCryptoApi_Mode_RPC_CLIENT,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
};
static SeosCryptoApi_Config cfgAuto =
{
    .mode = SeosCryptoApi_Mode_ROUTER,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
};

// Private Functions -----------------------------------------------------------

static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

static void
test_SeosCryptoApi(
    SeosCryptoApiH hCrypto)
{
    char desc[128];
    SeosCryptoApi_Mode mode = SeosCryptoApi_getMode(hCrypto);

    switch (mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        strcpy(desc, "SeosCryptoApi_Mode_LIBRARY");
        break;
    case SeosCryptoApi_Mode_ROUTER:
        strcpy(desc, "SeosCryptoApi_Mode_ROUTER");
        break;
    case SeosCryptoApi_Mode_RPC_CLIENT:
        strcpy(desc, "SeosCryptoApi_Mode_RPC_CLIENT");
        break;
    default:
        TEST_TRUE(1 == 0);
    }

    Debug_LOG_INFO("Testing Crypto API in %s mode:", desc);

    test_SeosCryptoApi_Agreement(hCrypto, mode);
    test_SeosCryptoApi_Cipher(hCrypto, mode);
    test_SeosCryptoApi_Digest(hCrypto, mode);
    test_SeosCryptoApi_Key(hCrypto, mode);
    test_SeosCryptoApi_Mac(hCrypto, mode);
    test_SeosCryptoApi_Rng(hCrypto, mode);
    test_SeosCryptoApi_Signature(hCrypto, mode);
}

static void
test_SeosCryptoApi_init_neg()
{
    SeosCryptoApiH hCrypto;
    SeosCryptoApi_Config badCfg;

    TEST_START();

    // Set these up here as the dataport is not const, so that the configs
    // should actually work
    cfgClient.impl.client.dataPort = SeosCryptoDataport;
    cfgAuto.impl.router.client = cfgClient.impl.client;
    cfgAuto.impl.router.lib = cfgLib.impl.lib;

    // Bad mode
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mode = 666;
    TEST_NOT_SUPP(SeosCryptoApi_init(&hCrypto, &badCfg));

    // No malloc pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    // No free pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    // No RNG pointer for LIB
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.impl.lib.rng.entropy = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    // No dataport for CLIENT, ROUTER
    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.impl.client.dataPort = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(SeosCryptoApi_Config));
    badCfg.impl.router.client.dataPort = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&hCrypto, &badCfg));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_free_neg()
{
    TEST_START();

    // No context
    TEST_INVAL_PARAM(SeosCryptoApi_free(NULL));

    TEST_FINISH();
}

// Public Functions -----------------------------------------------------------

int run()
{
    SeosCryptoApiH hCrypto;

    // We simply do negative tests here, as everything else below here covers
    // good API configurations and free'ing as well.
    test_SeosCryptoApi_init_neg();
    test_SeosCryptoApi_free_neg();

    Debug_LOG_INFO("");

    // Test LIBRARY mode
    TEST_SUCCESS(SeosCryptoApi_init(&hCrypto, &cfgLib));
    test_SeosCryptoApi(hCrypto);
    TEST_SUCCESS(SeosCryptoApi_free(hCrypto));

    Debug_LOG_INFO("");

    cfgClient.impl.client.dataPort = SeosCryptoDataport;

    // Test RPC CLIENT mode
    TEST_SUCCESS(Crypto_openSession());
    TEST_SUCCESS(SeosCryptoApi_init(&hCrypto, &cfgClient));
    test_SeosCryptoApi(hCrypto);
    TEST_SUCCESS(SeosCryptoApi_free(hCrypto));
    TEST_SUCCESS(Crypto_closeSession());

    Debug_LOG_INFO("");

    cfgAuto.impl.router.client = cfgClient.impl.client;
    cfgAuto.impl.router.lib = cfgLib.impl.lib;

    // Test ROUTER mode
    TEST_SUCCESS(Crypto_openSession());
    TEST_SUCCESS(SeosCryptoApi_init(&hCrypto, &cfgAuto));
    test_SeosCryptoApi(hCrypto);
    TEST_SUCCESS(SeosCryptoApi_free(hCrypto));
    TEST_SUCCESS(Crypto_closeSession());

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

/** @} */