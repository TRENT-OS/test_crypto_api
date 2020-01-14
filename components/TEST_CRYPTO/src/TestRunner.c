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

#include "LibDebug/Debug.h"

#include <camkes.h>
#include <string.h>

void TestAgreement_testAll(SeosCryptoApi* api);
void TestCipher_testAll(SeosCryptoApi* api);
void TestDigest_testAll(SeosCryptoApi* api);
void TestKey_testAll(SeosCryptoApi* api);
void TestMac_testAll(SeosCryptoApi* api);
void TestRng_testAll(SeosCryptoApi* api);
void TestSignature_testAll(SeosCryptoApi* api);

int entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}

int run()
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    SeosCryptoApi apiLocal, apiRemote;
    SeosCryptoApi_Config cfgLocal =
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
    SeosCryptoApi_Config cfgRemote =
    {
        .mode = SeosCryptoApi_Mode_RPC_CLIENT,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.client.dataPort = cryptoClientDataport
    };

    // Open local instance of API
    err = SeosCryptoApi_init(&apiLocal, &cfgLocal);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    // Open remote instance of API with pointer to Crypto component API object
    err = Crypto_openSession(&cfgRemote.impl.client.api);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_init(&apiRemote, &cfgRemote);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    Debug_PRINTF("Starting tests of SeosCryptoApi:\n");

    TestKey_testAll(&apiLocal);
    TestKey_testAll(&apiRemote);

    TestAgreement_testAll(&apiLocal);
    TestAgreement_testAll(&apiRemote);

    TestCipher_testAll(&apiLocal);
    TestCipher_testAll(&apiRemote);

    TestDigest_testAll(&apiLocal);
    TestDigest_testAll(&apiRemote);

    TestMac_testAll(&apiLocal);
    TestMac_testAll(&apiRemote);

    TestRng_testAll(&apiLocal);
    TestRng_testAll(&apiRemote);

    TestSignature_testAll(&apiLocal);
    TestSignature_testAll(&apiRemote);

    Debug_PRINTF("All tests completed.\n");

    err = SeosCryptoApi_free(&apiRemote);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);
    err = SeosCryptoApi_free(&apiLocal);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    err = Crypto_closeSession(cfgRemote.impl.client.api);
    Debug_ASSERT_PRINTFLN(err == SEOS_SUCCESS, "err %d", err);

    return 0;
}

/** @} */
