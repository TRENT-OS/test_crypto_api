/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

seos_err_t
Crypto_openSession(
    SeosCryptoApi_Ptr* api);

seos_err_t
Crypto_closeSession(
    SeosCryptoApi_Ptr api);