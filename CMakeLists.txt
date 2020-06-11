#
# Test Crypto API
#
# Copyright (C) 2019-2020, Hensoldt Cyber GmbH
#

cmake_minimum_required(VERSION 3.7.2)

os_set_config_file(config.h)

os_use_libs(
    OS_LIBS
    OS_LIBS_LOGGER
    OS_CRYPTO_WITH_RPC_CLIENT
    OS_CRYPTO_WITH_RPC_SERVER
)


#-------------------------------------------------------------------------------
project(tests_crypto_api C)

DeclareCAmkESComponent(
    test_OS_Crypto
    INCLUDES
        common
        components/CryptoRpcServer/src
    SOURCES
        components/Tests/src/test_OS_Crypto.c
        components/Tests/src/test_OS_CryptoSignature.c
        components/Tests/src/test_OS_CryptoCipher.c
        components/Tests/src/test_OS_CryptoRng.c
        components/Tests/src/test_OS_CryptoDigest.c
        components/Tests/src/test_OS_CryptoMac.c
        components/Tests/src/test_OS_CryptoAgreement.c
        components/Tests/src/test_OS_CryptoKey.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        os_crypto_with_rpc_client
)

DeclareCAmkESComponent(
    CryptoRpcServer
    INCLUDES
        common
        components/CryptoRpcServer/src
    SOURCES
        components/CryptoRpcServer/src/CryptoRpcServer.c
    C_FLAGS
        -Wall
        -Werror
    LIBS
        os_core_api
        os_libs
        os_crypto_with_rpc_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
