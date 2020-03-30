/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"

#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static void
test_OS_CryptoRng_getBytes_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char data[16];

    TEST_START(mode);

    TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto,  0, data, sizeof(data)));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_getBytes_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char data[16];

    TEST_START(mode);

    // Empty context
    TEST_INVAL_PARAM(OS_CryptoRng_getBytes(NULL, 0, data, sizeof(data)));

    // Invalid flag
    TEST_NOT_SUPP(OS_CryptoRng_getBytes(hCrypto, 666, data, sizeof(data)));

    // Empty buffer
    TEST_INVAL_PARAM(OS_CryptoRng_getBytes(hCrypto, 0, NULL, sizeof(data)));

    // Zero-length buffer
    TEST_INVAL_PARAM(OS_CryptoRng_getBytes(hCrypto, 0, data, 0));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_reSeed_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    TEST_START(mode);

    TEST_SUCCESS(OS_CryptoRng_reseed(hCrypto, seed, sizeof(seed)));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_reSeed_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    TEST_START(mode);

    // Empty context
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(NULL, seed, sizeof(seed)));

    // Empty buffer
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(hCrypto, NULL, sizeof(seed)));

    // Zero len buffer
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(hCrypto, seed, 0));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_reSeed_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    static unsigned char seedBuf[OS_Crypto_SIZE_DATAPORT + 1];
    size_t seedLen;

    TEST_START(mode);

    // Should go through, but will fail with aborted as RNG can only accept
    // limited amount of inputs per reseed
    seedLen = OS_Crypto_SIZE_DATAPORT;
    TEST_ABORTED(OS_CryptoRng_reseed(hCrypto, seedBuf, seedLen));

    // Should fail as input is too big
    seedLen = OS_Crypto_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(OS_CryptoRng_reseed(hCrypto, seedBuf, seedLen));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_getBytes_buffer(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    static unsigned char rngBuf[OS_Crypto_SIZE_DATAPORT + 1];
    size_t rngLen;

    TEST_START(mode);

    // Should go through, but will fail with aborted as RNG can only provide a
    // limited amount of bytes per call
    rngLen = OS_Crypto_SIZE_DATAPORT;
    TEST_ABORTED(OS_CryptoRng_getBytes(hCrypto, 0, rngBuf, rngLen));

    // Should fail as output is too big
    rngLen = OS_Crypto_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(OS_CryptoRng_getBytes(hCrypto, 0, rngBuf, rngLen));

    TEST_FINISH();
}

void
test_OS_CryptoRng(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    test_OS_CryptoRng_getBytes_pos(hCrypto, mode);
    test_OS_CryptoRng_getBytes_neg(hCrypto, mode);

    test_OS_CryptoRng_reSeed_pos(hCrypto, mode);
    test_OS_CryptoRng_reSeed_neg(hCrypto, mode);

    test_OS_CryptoRng_reSeed_buffer(hCrypto, mode);
    test_OS_CryptoRng_getBytes_buffer(hCrypto, mode);
}