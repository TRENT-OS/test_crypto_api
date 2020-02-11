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
void test_SeosCryptoApi_Agreement(SeosCryptoApi* api);
void test_SeosCryptoApi_Cipher(SeosCryptoApi* api);
void test_SeosCryptoApi_Digest(SeosCryptoApi* api);
void test_SeosCryptoApi_Key(SeosCryptoApi* api);
void test_SeosCryptoApi_Mac(SeosCryptoApi* api);
void test_SeosCryptoApi_Rng(SeosCryptoApi* api);
void test_SeosCryptoApi_Signature(SeosCryptoApi* api);

// Forward declaration
static int entropy(void*, unsigned char*, size_t);

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
static SeosCryptoApi_Config cfgRouter =
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
    SeosCryptoApi* api)
{
    char mode[128];

    switch (api->mode)
    {
    case SeosCryptoApi_Mode_LIBRARY:
        strcpy(mode, "SeosCryptoApi_Mode_LIBRARY");
        break;
    case SeosCryptoApi_Mode_ROUTER:
        strcpy(mode, "SeosCryptoApi_Mode_ROUTER");
        break;
    case SeosCryptoApi_Mode_RPC_CLIENT:
        strcpy(mode, "SeosCryptoApi_Mode_RPC_CLIENT");
        break;
    default:
        TEST_TRUE(1 == 0);
    }

    Debug_PRINTF("Testing Crypto API in %s mode:\n", mode);

    test_SeosCryptoApi_Agreement(api);
    test_SeosCryptoApi_Cipher(api);
    test_SeosCryptoApi_Digest(api);
    test_SeosCryptoApi_Key(api);
    test_SeosCryptoApi_Mac(api);
    test_SeosCryptoApi_Rng(api);
    test_SeosCryptoApi_Signature(api);
}

static void
test_SeosCryptoApi_init_neg()
{
    SeosCryptoApi api;
    SeosCryptoApi_Config badCfg;

    // Set these up here as the dataport is not const, so that the configs
    // should actually work
    cfgClient.impl.client.dataPort = SeosCryptoDataport;
    cfgRouter.impl.router.client = cfgClient.impl.client;
    cfgRouter.impl.router.lib = cfgLib.impl.lib;

    // Bad mode
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mode = 666;
    TEST_NOT_SUPP(SeosCryptoApi_init(&api, &badCfg));

    // No malloc pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    memcpy(&badCfg, &cfgRouter, sizeof(SeosCryptoApi_Config));
    badCfg.mem.malloc = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    // No free pointer in all modi
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    memcpy(&badCfg, &cfgRouter, sizeof(SeosCryptoApi_Config));
    badCfg.mem.free = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    // No RNG pointer for LIB
    memcpy(&badCfg, &cfgLib, sizeof(SeosCryptoApi_Config));
    badCfg.impl.lib.rng.entropy = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    // No dataport for CLIENT, ROUTER
    memcpy(&badCfg, &cfgClient, sizeof(SeosCryptoApi_Config));
    badCfg.impl.client.dataPort = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    memcpy(&badCfg, &cfgRouter, sizeof(SeosCryptoApi_Config));
    badCfg.impl.router.client.dataPort = NULL;
    TEST_INVAL_PARAM(SeosCryptoApi_init(&api, &badCfg));

    TEST_OK();
}

static void
test_SeosCryptoApi_free_neg()
{
    // No context
    TEST_INVAL_PARAM(SeosCryptoApi_free(NULL));

    TEST_OK();
}

// Public Functions -----------------------------------------------------------

int run()
{
    SeosCryptoApi api;

    // We simply do negative tests here, as everything else below here covers
    // good API configurations and free'ing as well.
    test_SeosCryptoApi_init_neg();
    test_SeosCryptoApi_free_neg();

    Debug_PRINTF("\n");

    // Test LIBRARY mode
    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgLib));
    test_SeosCryptoApi(&api);
    TEST_SUCCESS(SeosCryptoApi_free(&api));

    Debug_PRINTF("\n");

    cfgClient.impl.client.dataPort = SeosCryptoDataport;

    // Test RPC CLIENT mode
    TEST_SUCCESS(Crypto_openSession());
    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgClient));
    test_SeosCryptoApi(&api);
    TEST_SUCCESS(SeosCryptoApi_free(&api));
    TEST_SUCCESS(Crypto_closeSession());

    Debug_PRINTF("\n");

    cfgRouter.impl.router.client = cfgClient.impl.client;
    cfgRouter.impl.router.lib = cfgLib.impl.lib;

    // Test ROUTER mode
    TEST_SUCCESS(Crypto_openSession());
    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgRouter));
    test_SeosCryptoApi(&api);
    TEST_SUCCESS(SeosCryptoApi_free(&api));
    TEST_SUCCESS(Crypto_closeSession());

    Debug_PRINTF("All tests successfully completed.\n");

    return 0;
}

/** @} */