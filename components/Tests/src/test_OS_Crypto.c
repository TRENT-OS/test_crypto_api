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

#include "OS_Crypto.h"

#include "TestMacros.h"

#include <camkes.h>
#include <string.h>

// These are the tests for the sub-modules of the API
void test_OS_CryptoAgreement(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoCipher(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoDigest(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoKey(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoMac(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoRng(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);
void test_OS_CryptoSignature(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode);

// Forward declaration
static int entropy(
    void*, unsigned char*, size_t);

// These are all the configurations of the Crypto API we want to test
static OS_Crypto_Config_t cfgLib =
{
    .mode = OS_Crypto_MODE_LIBRARY,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
    .impl.lib.rng.entropy = entropy,
};
static OS_Crypto_Config_t cfgClient =
{
    .mode = OS_Crypto_MODE_RPC_CLIENT,
    .mem = {
        .malloc = malloc,
        .free = free,
    },
};
static OS_Crypto_Config_t cfgAuto =
{
    .mode = OS_Crypto_MODE_ROUTER,
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
test_OS_Crypto(
    OS_Crypto_Handle_t hCrypto)
{
    char desc[128];
    OS_Crypto_Mode_t mode = OS_Crypto_getMode(hCrypto);

    switch (mode)
    {
    case OS_Crypto_MODE_LIBRARY:
        strcpy(desc, "OS_Crypto_MODE_LIBRARY");
        break;
    case OS_Crypto_MODE_ROUTER:
        strcpy(desc, "OS_Crypto_MODE_ROUTER");
        break;
    case OS_Crypto_MODE_RPC_CLIENT:
        strcpy(desc, "OS_Crypto_MODE_RPC_CLIENT");
        break;
    default:
        TEST_TRUE(1 == 0);
    }

    Debug_LOG_INFO("Testing Crypto API in %s mode:", desc);

    test_OS_CryptoAgreement(hCrypto, mode);
    test_OS_CryptoCipher(hCrypto, mode);
    test_OS_CryptoDigest(hCrypto, mode);
    test_OS_CryptoKey(hCrypto, mode);
    test_OS_CryptoMac(hCrypto, mode);
    test_OS_CryptoRng(hCrypto, mode);
    test_OS_CryptoSignature(hCrypto, mode);
}

static void
test_OS_Crypto_init_neg()
{
    OS_Crypto_Handle_t hCrypto;
    OS_Crypto_Config_t badCfg;

    TEST_START();

    // Set these up here as the dataport is not const, so that the configs
    // should actually work
    cfgClient.impl.client.dataPort = SeosCryptoDataport;
    cfgAuto.impl.router.client = cfgClient.impl.client;
    cfgAuto.impl.router.lib = cfgLib.impl.lib;

    // Bad mode
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.mode = 666;
    TEST_NOT_SUPP(OS_Crypto_init(&hCrypto, &badCfg));

    // No malloc pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(OS_Crypto_Config_t));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // No free pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(OS_Crypto_Config_t));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // No RNG pointer for LIB
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.impl.lib.rng.entropy = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // No dataport for CLIENT, ROUTER
    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.impl.client.dataPort = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgAuto, sizeof(OS_Crypto_Config_t));
    badCfg.impl.router.client.dataPort = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    TEST_FINISH();
}

static void
test_OS_Crypto_free_neg()
{
    TEST_START();

    // No context
    TEST_INVAL_PARAM(OS_Crypto_free(NULL));

    TEST_FINISH();
}

// Public Functions -----------------------------------------------------------

int run()
{
    OS_Crypto_Handle_t hCrypto;

    // We simply do negative tests here, as everything else below here covers
    // good API configurations and free'ing as well.
    test_OS_Crypto_init_neg();
    test_OS_Crypto_free_neg();

    Debug_LOG_INFO("");

    // Test LIBRARY mode
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgLib));
    test_OS_Crypto(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));

    Debug_LOG_INFO("");

    cfgClient.impl.client.dataPort = SeosCryptoDataport;

    // Test RPC CLIENT mode
    TEST_SUCCESS(CryptoRpcServer_openSession());
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgClient));
    test_OS_Crypto(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));
    TEST_SUCCESS(CryptoRpcServer_closeSession());

    Debug_LOG_INFO("");

    cfgAuto.impl.router.client = cfgClient.impl.client;
    cfgAuto.impl.router.lib = cfgLib.impl.lib;

    // Test ROUTER mode
    TEST_SUCCESS(CryptoRpcServer_openSession());
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgAuto));
    test_OS_Crypto(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));
    TEST_SUCCESS(CryptoRpcServer_closeSession());

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

/** @} */