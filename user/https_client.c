#include "https_client.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iconv.h>


extern const char *taoao_root_cert;


struct ssl_conn s;
struct host_info host;
int u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen) ;
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen) ;

void parse_url(char* url,struct host_info* host)
{
    char* ptr_start;
    char* ptr_end;
    char* colon; 
    printf("url:%s \n",url);
    
    if(strstr(url,"https://") != NULL)
    {
            host->secure = 1;
            ptr_start = url + strlen("https://");
    }
    else if(strstr(url,"http://") != NULL)
    {
            host->secure = 0;
            ptr_start = url + strlen("http://");
    }
    else
    {
            host->secure = 1;
            ptr_start = url;
            printf("[warning]url not a complete format:%s \n",url); 
    }
    
    /*port*/
    colon = strchr(ptr_start,':');
    if(colon != NULL)
    {
        snprintf(host->port,sizeof(host->port),"%d",atoi(colon+strlen(":")));
    }
    else
    {
        snprintf(host->port,sizeof(host->port),"%d",host->secure?443:80);
    }

    /*path*/
    ptr_end = strchr(ptr_start,'/');
    if(ptr_end != NULL)
    {
        strcpy(host->path,ptr_end);
    }
    else
    {
        strcpy(host->path,"/");
    }

    /*name*/
    if(colon != NULL)
    {
        memcpy(host->name,ptr_start,colon - ptr_start);
    }
    else
    {
        if(ptr_end != NULL)
        {
            memcpy(host->name,ptr_start,ptr_end - ptr_start);
        }
        else
        {
            strcpy(host->name,ptr_start);
        }
    }

    printf(" name:%s \n port:%s \n path:%s \n",host->name,host->port,host->path);
    
}
/***************************************************************/
void ssl_init(struct ssl_conn* s)
{
	/*
	* 0. Initialize the RNG and the session data
	*/
    mbedtls_net_init( &s->server_fd );
    mbedtls_ssl_init( &s->ssl );
    mbedtls_ssl_config_init( &s->conf );
    mbedtls_x509_crt_init( &s->cacert );
    mbedtls_ctr_drbg_init( &s->ctr_drbg );

    s->client_cert = (char*)taoao_root_cert;
}

void ssl_destroy(struct ssl_conn* s)
{
    printf("...%s \n",__FUNCTION__);
    mbedtls_ssl_close_notify( &s->ssl );
    mbedtls_net_free( &s->server_fd );

    mbedtls_x509_crt_free( &s->cacert );
    mbedtls_ssl_free( &s->ssl );
    mbedtls_ssl_config_free( &s->conf );
    mbedtls_ctr_drbg_free( &s->ctr_drbg );
    mbedtls_entropy_free( &s->entropy );
}

void ssl_connect(struct ssl_conn* s, char* url)
{
    int ret = 1;
    const char *pers = "ssl_client1";
    

    memset(&host,0,sizeof(host));
    parse_url(url,&host);

    //return;
    
    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    mbedtls_entropy_init( &s->entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &s->ctr_drbg, mbedtls_entropy_func, &s->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

    ret = mbedtls_x509_crt_parse( &s->cacert, (const unsigned char *) s->client_cert,
                          strlen(s->client_cert) + 1);
    if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    printf( "  . Connecting to tcp/%s/%s...", host.name, host.port );
    fflush( stdout );

    if( ( ret = mbedtls_net_connect( &s->server_fd, host.name,
                                          host.port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

        /*
     * 2. Setup stuff
     */
    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &s->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &s->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &s->conf, &s->cacert, NULL );
    mbedtls_ssl_conf_rng( &s->conf, mbedtls_ctr_drbg_random, &s->ctr_drbg );
    //mbedtls_ssl_conf_dbg( &s->conf, my_debug, stdout );

    if( ( ret = mbedtls_ssl_setup( &s->ssl, &s->conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &s->ssl, host.name ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_ssl_set_bio( &s->ssl, &s->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

     /*
     * 4. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &s->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }
    
    printf( " ok\n" );
    
        /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );
    uint32_t flags;
    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &s->ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
    }
    else
        printf( " ok\n" );


    exit:
            return;
         
		
}

int ssl_write(struct ssl_conn* s,char* buf,int len)
{
    int ret;
        /*
     * 6. Write the GET request
     */
    printf( "  > Write to server:" );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_write( &s->ssl, buf, len ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            return 1;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s", len, (char *) buf );
    return 0;
}
char content_buf[256];
char utf8_content_buf[512];

void parse_content(char* in_buf,int len)
{   
   static char content;
   char* ptr = NULL;

   memset(content_buf,0,sizeof(content_buf));
   ptr = strstr(in_buf,"\r\n\r\n");
   if( ptr != NULL)
    {
        content = 1;
        ptr += strlen("\r\n\r\n");
        strcat(content_buf,ptr);
        g2u(content_buf,strlen(content_buf),utf8_content_buf,sizeof(utf8_content_buf));
        printf("    GBK->UTF-8:\n%s\n",utf8_content_buf);
        return;
    }
   
}

void ssl_read(struct ssl_conn* s)
{
    int len,ret;
    char buf[1024];
     /*
     * 7. Read the HTTP response
     */
    printf( "  < Read from server:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &s->ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret < 0 )
        {
            printf( "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            break;
        }

        if( ret == 0 )
        {
            printf( "\n\nEOF\n\n" );
            
            break;
        }

        len = ret;
        printf( " %d bytes read\n\n", len);
        parse_content((char*)buf,len);
    }
    while( 1 );
}
/*https://tcc.taobao.com/cc/json/mobile_tel_segment.htm?tel=13632947601*/
int main(int argc,char** argv)
{
    if(argc<2)
        {
            printf("Usage...\n");
            return 1;
        }
    
    struct ssl_conn*s;
    s =  (struct ssl_conn*)malloc(sizeof(struct ssl_conn));
    ssl_init(s); 
    
    char url[128]="https://tcc.taobao.com/cc/json/mobile_tel_segment.htm?tel=";
    ssl_connect(s,url);

    char buf[1024];
    int len;
    strcat(host.path,argv[1]);
    len = snprintf(buf,sizeof(buf),"GET %s HTTP/1.1\r\nHost: %s\r\nContent-Language: en-US\r\nUser-Agent:niro\r\nConnection:close\r\nContent-Length:%d\r\n\r\n",
                                    host.path,host.name,0);
    
    ssl_write(s,buf,len);
    ssl_read(s);
    ssl_destroy(s);
    return 0;
    
}
int code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen,  
        char *outbuf, size_t outlen) {  
    iconv_t cd;  
    char **pin = &inbuf;  
    char **pout = &outbuf;  
  
    cd = iconv_open(to_charset, from_charset);  
    if (cd == 0)  
        return -1;  
    memset(outbuf, 0, outlen);  
    if (iconv(cd, pin, &inlen, pout, &outlen) == -1)  
        return -1;  
    iconv_close(cd);  
    *pout = '\0';  
  
    return 0;  
}  
  
int u2g(char *inbuf, size_t inlen, char *outbuf, size_t outlen) 
{  
    return code_convert("utf-8", "gb2312", inbuf, inlen, outbuf, outlen);  
}  
  
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen) 
{  
    return code_convert("gb2312", "utf-8", inbuf, inlen, outbuf, outlen);  
}

