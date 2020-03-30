/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"

seos_err_t
CryptoRpcServer_openSession();

int
CryptoRpcServer_hasObject(
    OS_CryptoLib_Object_ptr ptr);

seos_err_t
CryptoRpcServer_loadKey(
    OS_CryptoLib_Object_ptr* ptr);

seos_err_t
CryptoRpcServer_closeSession();