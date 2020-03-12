/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosCryptoApi.h"

seos_err_t
CryptoRpcServer_openSession();

int
CryptoRpcServer_hasObject(
    SeosCryptoLib_Object ptr);

seos_err_t
CryptoRpcServer_loadKey(
    SeosCryptoLib_Object* ptr);

seos_err_t
CryptoRpcServer_closeSession();