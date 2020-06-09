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
#include "ObjectLocation.h"

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
    .mode = OS_Crypto_MODE_LIBRARY_ONLY,
    .library.rng.entropy = entropy,
};
static OS_Crypto_Config_t cfgRemote =
{
    .mode = OS_Crypto_MODE_CLIENT_ONLY,
    .dataport = OS_DATAPORT_ASSIGN(CryptoLibDataport)
};
static OS_Crypto_Config_t cfgClient =
{
    .mode = OS_Crypto_MODE_CLIENT,
    .dataport = OS_DATAPORT_ASSIGN(CryptoLibDataport),
    .library.rng.entropy = entropy
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
    case OS_Crypto_MODE_LIBRARY_ONLY:
        strcpy(desc, "OS_Crypto_MODE_LIBRARY_ONLY");
        break;
    case OS_Crypto_MODE_CLIENT:
        strcpy(desc, "OS_Crypto_MODE_CLIENT");
        break;
    case OS_Crypto_MODE_CLIENT_ONLY:
        strcpy(desc, "OS_Crypto_MODE_CLIENT_ONLY");
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

    // Bad mode
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.mode = 666;
    TEST_NOT_SUPP(OS_Crypto_init(&hCrypto, &badCfg));

    // Have only calloc but not free set in all modi
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = NULL;
    badCfg.memory.free = free;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgRemote, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = NULL;
    badCfg.memory.free = free;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = NULL;
    badCfg.memory.free = free;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // Have only free but not calloc set in all modi
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = calloc;
    badCfg.memory.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgRemote, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = calloc;
    badCfg.memory.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.memory.calloc = calloc;
    badCfg.memory.free = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // No RNG pointer for LIB
    memcpy(&badCfg, &cfgLib, sizeof(OS_Crypto_Config_t));
    badCfg.library.rng.entropy = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    // No dataport for CLIENT, ROUTER
    memcpy(&badCfg, &cfgRemote, sizeof(OS_Crypto_Config_t));
    badCfg.dataport.io = NULL;
    TEST_INVAL_PARAM(OS_Crypto_init(&hCrypto, &badCfg));

    memcpy(&badCfg, &cfgClient, sizeof(OS_Crypto_Config_t));
    badCfg.dataport.io = NULL;
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

static void
test_OS_Crypto_migrateLibObject_pos(
    OS_Crypto_Handle_t hCrypto)
{
    static uint8_t expectedKey[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    static OS_CryptoKey_Data_t keyData;
    OS_CryptoKey_Handle_t hKey;
    CryptoLib_Object_ptr ptr;

    TEST_START();

    // Let the remote side load a key into its address space
    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));

    // Mograte the key so it can be accessed through or local API instance
    TEST_SUCCESS(OS_Crypto_migrateLibObject(&hKey, hCrypto, ptr, false));
    // Check that the key can now really be used by exporting it and checking it
    // against an expected value..
    TEST_SUCCESS(OS_CryptoKey_export(hKey, &keyData))
    TEST_TRUE(!memcmp(keyData.data.aes.bytes, expectedKey, sizeof(expectedKey)));

    TEST_SUCCESS(OS_CryptoKey_free(hKey));

    TEST_FINISH();
}

static void
test_OS_Crypto_migrateLibObject_neg(
    OS_Crypto_Handle_t hCrypto)
{
    OS_CryptoKey_Handle_t hKey;
    CryptoLib_Object_ptr ptr;

    TEST_START();

    // Let the remote side load a key into its address space
    TEST_SUCCESS(CryptoRpcServer_loadKey(&ptr));

    // Empty key
    TEST_INVAL_PARAM(OS_Crypto_migrateLibObject(NULL, hCrypto, ptr, false));

    // Empty ctx
    TEST_INVAL_PARAM(OS_Crypto_migrateLibObject(&hKey, NULL, ptr, false));

    // Invalid remote pointer
    TEST_INVAL_PARAM(OS_Crypto_migrateLibObject(&hKey, hCrypto, NULL, false));

    // Need to migrate it successfully, so we can free the crypto lib object
    // through freeing the API proxy object
    TEST_SUCCESS(OS_Crypto_migrateLibObject(&hKey, hCrypto, ptr, false));
    TEST_SUCCESS(OS_CryptoKey_free(hKey));

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

    // Test LIBRARY_ONLY mode
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgLib));
    test_OS_Crypto(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));

    Debug_LOG_INFO("");

    // Test CLIENT_ONLY mode
    TEST_SUCCESS(CryptoRpcServer_openSession());
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgRemote));
    test_OS_Crypto(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));
    TEST_SUCCESS(CryptoRpcServer_closeSession());

    Debug_LOG_INFO("");

    // Test CLIENT mode
    TEST_SUCCESS(CryptoRpcServer_openSession());
    TEST_SUCCESS(OS_Crypto_init(&hCrypto, &cfgClient));
    test_OS_Crypto(hCrypto);
    test_OS_Crypto_migrateLibObject_pos(hCrypto);
    test_OS_Crypto_migrateLibObject_neg(hCrypto);
    TEST_SUCCESS(OS_Crypto_free(hCrypto));
    TEST_SUCCESS(CryptoRpcServer_closeSession());

    Debug_LOG_INFO("All tests successfully completed.");

    return 0;
}

/** @} */