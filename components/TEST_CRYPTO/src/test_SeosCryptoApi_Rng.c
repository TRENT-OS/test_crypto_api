/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "SeosCryptoApi.h"

#include "TestMacros.h"

#include <string.h>

// -----------------------------------------------------------------------------

static void
test_SeosCryptoApi_Rng_getBytes_pos(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char data[16];

    err = SeosCryptoApi_Rng_getBytes(api,  0, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode);
}

static void
test_SeosCryptoApi_Rng_getBytes_neg(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char data[16];

    // Empty context
    err = SeosCryptoApi_Rng_getBytes(NULL, 0, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Invalid flag
    err = SeosCryptoApi_Rng_getBytes(api, 666, data, sizeof(data));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_NOT_SUPPORTED == err, "err %d", err);

    // Empty buffer
    err = SeosCryptoApi_Rng_getBytes(api, 0, NULL, sizeof(data));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    // Zero-length buffer
    err = SeosCryptoApi_Rng_getBytes(api, 0, data, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    TEST_OK(api->mode);
}

static void
test_SeosCryptoApi_Rng_reSeed_pos(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    err = SeosCryptoApi_Rng_reseed(api, seed, sizeof(seed));
    Debug_ASSERT_PRINTFLN(SEOS_SUCCESS == err, "err %d", err);

    TEST_OK(api->mode);
}

static void
test_SeosCryptoApi_Rng_reSeed_neg(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    char seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    err = SeosCryptoApi_Rng_reseed(NULL, seed, sizeof(seed));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Rng_reseed(api, NULL, sizeof(seed));
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    err = SeosCryptoApi_Rng_reseed(api, seed, 0);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INVALID_PARAMETER == err, "err %d", err);

    TEST_OK(api->mode);
}

static void
test_SeosCryptoApi_Rng_reSeed_buffer(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned char seedBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t seedLen;

    // Should go through, but will fail with aborted as RNG can only accept
    // limited amount of inputs per reseed
    seedLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Rng_reseed(api, seedBuf, seedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Should fail as input is too big
    seedLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Rng_reseed(api, seedBuf, seedLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    TEST_OK(api->mode);
}

static void
test_SeosCryptoApi_Rng_getBytes_buffer(
    SeosCryptoApi* api)
{
    seos_err_t err = SEOS_ERROR_GENERIC;
    static unsigned char rngBuf[SeosCryptoApi_SIZE_DATAPORT + 1];
    size_t rngLen;

    // Should go through, but will fail with aborted as RNG can only provide a
    // limited amount of bytes per call
    rngLen = SeosCryptoApi_SIZE_DATAPORT;
    err = SeosCryptoApi_Rng_getBytes(api, 0, rngBuf, rngLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_ABORTED == err, "err %d", err);

    // Should fail as output is too big
    rngLen = SeosCryptoApi_SIZE_DATAPORT + 1;
    err = SeosCryptoApi_Rng_getBytes(api, 0, rngBuf, rngLen);
    Debug_ASSERT_PRINTFLN(SEOS_ERROR_INSUFFICIENT_SPACE == err, "err %d", err);

    TEST_OK(api->mode);
}

void
test_SeosCryptoApi_Rng(
    SeosCryptoApi* api)
{
    test_SeosCryptoApi_Rng_getBytes_pos(api);
    test_SeosCryptoApi_Rng_getBytes_neg(api);

    test_SeosCryptoApi_Rng_reSeed_pos(api);
    test_SeosCryptoApi_Rng_reSeed_neg(api);

    test_SeosCryptoApi_Rng_reSeed_buffer(api);
    test_SeosCryptoApi_Rng_getBytes_buffer(api);
}