cmake_minimum_required(VERSION 3.7.2)

seos_set_config_file(config.h)

seos_use_libs(
    SEOS_LIBS
    SEOS_LIBS_LOGGER
    SEOS_CRYPTO_WITH_RPC_CLIENT
    SEOS_CRYPTO_WITH_RPC_SERVER
    SEOS_CRYPTO_IMPL_MBEDTLS
)

project(tests_crypto_api C)

DeclareCAmkESComponent(test_SeosCryptoApi
    INCLUDES
        common
        components/CryptoRpcServer/src
    SOURCES
        components/Tests/src/test_SeosCryptoApi.c
        components/Tests/src/test_SeosCryptoApi_Signature.c
        components/Tests/src/test_SeosCryptoApi_Cipher.c
        components/Tests/src/test_SeosCryptoApi_Rng.c
        components/Tests/src/test_SeosCryptoApi_Digest.c
        components/Tests/src/test_SeosCryptoApi_Mac.c
        components/Tests/src/test_SeosCryptoApi_Agreement.c
        components/Tests/src/test_SeosCryptoApi_Key.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_crypto_with_rpc_client
)

DeclareCAmkESComponent(CryptoRpcServer
    INCLUDES
        common
        components/CryptoRpcServer/src
    SOURCES
        components/CryptoRpcServer/src/CryptoRpcServer.c
    C_FLAGS
        -Wall -Werror
    LIBS
        seos_core_api
        seos_libs
        seos_crypto_with_rpc_server
)

DeclareCAmkESRootserver(main.camkes)
GenerateCAmkESRootServer()
GenerateSimulateScript()
