/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

seos_err_t
Crypto_openSession();

typedef void* Object_Ptr;

int
Crypto_hasObject(
    Object_Ptr ptr);

seos_err_t
Crypto_closeSession();