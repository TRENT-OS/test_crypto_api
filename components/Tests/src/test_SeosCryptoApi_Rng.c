/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static void
test_SeosCryptoApi_Rng_getBytes_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    char data[16];

    TEST_START(mode);

    TEST_SUCCESS(SeosCryptoApi_Rng_getBytes(hCrypto,  0, data, sizeof(data)));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Rng_getBytes_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    char data[16];

    TEST_START(mode);

    // Empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_getBytes(NULL, 0, data, sizeof(data)));

    // Invalid flag
    TEST_NOT_SUPP(SeosCryptoApi_Rng_getBytes(hCrypto, 666, data, sizeof(data)));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_getBytes(hCrypto, 0, NULL, sizeof(data)));

    // Zero-length buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_getBytes(hCrypto, 0, data, 0));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Rng_reSeed_pos(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    TEST_START(mode);

    TEST_SUCCESS(SeosCryptoApi_Rng_reseed(hCrypto, seed, sizeof(seed)));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Rng_reSeed_neg(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    TEST_START(mode);

    // Empty context
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_reseed(NULL, seed, sizeof(seed)));

    // Empty buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_reseed(hCrypto, NULL, sizeof(seed)));

    // Zero len buffer
    TEST_INVAL_PARAM(SeosCryptoApi_Rng_reseed(hCrypto, seed, 0));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Rng_reSeed_buffer(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    static unsigned char seedBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t seedLen;

    TEST_START(mode);

    // Should go through, but will fail with aborted as RNG can only accept
    // limited amount of inputs per reseed
    seedLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_ABORTED(SeosCryptoApi_Rng_reseed(hCrypto, seedBuf, seedLen));

    // Should fail as input is too big
    seedLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Rng_reseed(hCrypto, seedBuf, seedLen));

    TEST_FINISH();
}

static void
test_SeosCryptoApi_Rng_getBytes_buffer(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    static unsigned char rngBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t rngLen;

    TEST_START(mode);

    // Should go through, but will fail with aborted as RNG can only provide a
    // limited amount of bytes per call
    rngLen = SeosCryptoApi_SIZE_DATAPORT;
    TEST_ABORTED(SeosCryptoApi_Rng_getBytes(hCrypto, 0, rngBuf, rngLen));

    // Should fail as output is too big
    rngLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    TEST_INSUFF_SPACE(SeosCryptoApi_Rng_getBytes(hCrypto, 0, rngBuf, rngLen));

    TEST_FINISH();
}

void
test_SeosCryptoApi_Rng(
    SeosCryptoApiH           hCrypto,
    const SeosCryptoApi_Mode mode)
{
    test_SeosCryptoApi_Rng_getBytes_pos(hCrypto, mode);
    test_SeosCryptoApi_Rng_getBytes_neg(hCrypto, mode);

    test_SeosCryptoApi_Rng_reSeed_pos(hCrypto, mode);
    test_SeosCryptoApi_Rng_reSeed_neg(hCrypto, mode);

    test_SeosCryptoApi_Rng_reSeed_buffer(hCrypto, mode);
    test_SeosCryptoApi_Rng_getBytes_buffer(hCrypto, mode);
}