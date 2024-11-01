/**
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#include "OS_Crypto.h"

#include "lib_macros/Test.h"

#include <string.h>

// -----------------------------------------------------------------------------

static void
test_OS_CryptoRng_getBytes_pos(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char data[16];

    TEST_START("i", mode);

    TEST_SUCCESS(OS_CryptoRng_getBytes(hCrypto,  0, data, sizeof(data)));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_getBytes_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char data[16];

    TEST_START("i", mode);

    // Empty crypto handle
    TEST_INVAL_PARAM(OS_CryptoRng_getBytes(NULL, 0, data, sizeof(data)));

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

    TEST_START("i", mode);

    TEST_SUCCESS(OS_CryptoRng_reseed(hCrypto, seed, sizeof(seed)));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_reSeed_neg(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    TEST_START("i", mode);

    // Empty crypt handle
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(NULL, seed, sizeof(seed)));

    // Empty buffer
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(hCrypto, NULL, sizeof(seed)));

    // Zero len buffer
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(hCrypto, seed, 0));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_reSeed_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    static unsigned char seedBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t seedLen;

    TEST_START("i", mode);

    // Should go through, but will fail with aborted as RNG can only accept
    // limited amount of inputs per reseed
    seedLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_ABORTED(OS_CryptoRng_reseed(hCrypto, seedBuf, seedLen));

    // Should fail as input is too big
    seedLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoRng_reseed(hCrypto, seedBuf, seedLen));

    TEST_FINISH();
}

static void
test_OS_CryptoRng_getBytes_dataport(
    OS_Crypto_Handle_t     hCrypto,
    const OS_Crypto_Mode_t mode)
{
    static unsigned char rngBuf[OS_DATAPORT_DEFAULT_SIZE + 1];
    size_t rngLen;

    TEST_START("i", mode);

    // Should go through, but will fail with aborted as RNG can only provide a
    // limited amount of bytes per call
    rngLen = OS_DATAPORT_DEFAULT_SIZE;
    TEST_ABORTED(OS_CryptoRng_getBytes(hCrypto, 0, rngBuf, rngLen));

    // Should fail as output is too big
    rngLen = OS_DATAPORT_DEFAULT_SIZE + 1;
    TEST_INVAL_PARAM(OS_CryptoRng_getBytes(hCrypto, 0, rngBuf, rngLen));

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

    switch (mode)
    {
    case OS_Crypto_MODE_CLIENT:
        test_OS_CryptoRng_reSeed_dataport(hCrypto, mode);
        test_OS_CryptoRng_getBytes_dataport(hCrypto, mode);
        break;
    default:
        break;
    }
}