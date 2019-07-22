#ifndef HTTPS_CLIENT_H_
#define HTTPS_CLIENT_H_
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>

// this must be ahead of any mbedtls header files so the local mbedtls/config.h can be properly referenced
#include "mbedtls/config.h"

#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

struct ssl_conn
{
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    char* client_cert;
};

struct host_info
{
    char name[128];
    char port[16];
    char path[512];
    char secure;
};




















































#endif
