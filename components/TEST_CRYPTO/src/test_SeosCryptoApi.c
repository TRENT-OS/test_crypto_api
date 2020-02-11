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

void test_SeosCryptoApi_Agreement(SeosCryptoApi* api);
void test_SeosCryptoApi_Cipher(SeosCryptoApi* api);
void test_SeosCryptoApi_Digest(SeosCryptoApi* api);
void test_SeosCryptoApi_Key(SeosCryptoApi* api);
void test_SeosCryptoApi_Mac(SeosCryptoApi* api);
void test_SeosCryptoApi_Rng(SeosCryptoApi* api);
void test_SeosCryptoApi_Signature(SeosCryptoApi* api);

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

// Public Functions -----------------------------------------------------------

int run()
{
    SeosCryptoApi api;
    SeosCryptoApi_Config cfgLib =
    {
        .mode = SeosCryptoApi_Mode_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng = {
            .entropy = entropy,
            .context = NULL
        }
    };
    SeosCryptoApi_Config cfgClient =
    {
        .mode = SeosCryptoApi_Mode_RPC_CLIENT,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.client.dataPort = SeosCryptoDataport
    };
    SeosCryptoApi_Config cfgRouter =
    {
        .mode = SeosCryptoApi_Mode_ROUTER,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        // The router switches between client and lib, so we just copy their
        // respective configs here..
        .impl.router.client = cfgClient.impl.client,
        .impl.router.lib = cfgLib.impl.lib,
    };

    // Test LIBRARY mode
    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgLib));
    test_SeosCryptoApi(&api);
    TEST_SUCCESS(SeosCryptoApi_free(&api));

    Debug_PRINTF("\n");

    // Test RPC CLIENT mode
    TEST_SUCCESS(Crypto_openSession());
    TEST_SUCCESS(SeosCryptoApi_init(&api, &cfgClient));
    test_SeosCryptoApi(&api);
    TEST_SUCCESS(SeosCryptoApi_free(&api));
    TEST_SUCCESS(Crypto_closeSession());

    Debug_PRINTF("\n");

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