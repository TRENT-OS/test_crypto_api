/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

seos_err_t
Crypto_openSession();

int
Crypto_hasObject(
    SeosCryptoLib_Object ptr);

seos_err_t
Crypto_loadKey(
    SeosCryptoLib_Object* ptr);

seos_err_t
Crypto_closeSession();