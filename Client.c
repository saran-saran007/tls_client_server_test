#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include<stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#ifdef DEBUG
#include <openssl/trace.h>
#endif

#define FAIL    -1

/*** Begin Openssl internal print functions ***/
extern int ossl_x509_print_ex_brief(BIO *bio, X509 *cert, unsigned long neg_cflags);

int print_certs(BIO *bio, const STACK_OF(X509) *certs)
{
    int i;

    if (certs == NULL || sk_X509_num(certs) <= 0)
        return BIO_printf(bio, "    (no certificates)\n") >= 0;

    for (i = 0; i < sk_X509_num(certs); i++) {
        X509 *cert = sk_X509_value(certs, i);

        if (cert != NULL) {
            if (!ossl_x509_print_ex_brief(bio, cert, 0))
                return 0;
            if (!X509V3_extensions_print(bio, NULL,
                                         X509_get0_extensions(cert),
                                         X509_FLAG_EXTENSIONS_ONLY_KID, 8))
                return 0;
            }
    }
    return 1;
}

int print_store_certs(BIO *bio, X509_STORE *store)
{
    if (store != NULL) {
        STACK_OF(X509) *certs = X509_STORE_get1_all_certs(store);
        int ret = print_certs(bio, certs);

        sk_X509_pop_free(certs, X509_free);
        return ret;
    } else {
        return BIO_printf(bio, "    (no trusted store)\n") >= 0;
    }
}

void apps_ssl_info_callback(const SSL *s, int where, int ret)
{
    const char *str;
    int w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP) {
        BIO_printf(BIO_new_fp(stdout,0), "%s:%s\n", str, SSL_state_string_long(s));
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        BIO_printf(BIO_new_fp(stdout,0), "SSL3 alert %s:%s:%s\n",
                   str,
                   SSL_alert_type_string_long(ret),
                   SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0)
            BIO_printf(BIO_new_fp(stdout,0), "%s:failed in %s\n",
                       str, SSL_state_string_long(s));
        else if (ret < 0)
            BIO_printf(BIO_new_fp(stdout,0), "%s:error in %s\n",
                       str, SSL_state_string_long(s));
    }
}

/*** END Openssl internal print functions ***/

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

SSL_CTX* InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

void enable_hostname_verification(SSL *ssl, const char *domain)
{
	X509_VERIFY_PARAM *param = NULL;
        int ret = 0;

	param = SSL_get0_param(ssl);

	/* Enable automatic hostname checks */
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (!X509_VERIFY_PARAM_set1_host(param, domain, sizeof(domain) - 1)) {
		// handle error
		return;
	}

	ret = SSL_set_tlsext_host_name(ssl, domain);
        if (ret != 1)
        {
            printf("### unable to set hostname to: %s ###", domain);
        } else {
            printf("### set SNI  to: %s ###", domain);
        }
	/* Enable peer verification, (with a non-null callback if desired) */
	SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
}

int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    X509_STORE *cert_store = NULL;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes, ret = 0;
    char *hostname, *portnum, *domain;
    if ( count != 4 )
    {
        printf("usage: %s <hostname> <portnum> <<domain>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    domain=strings[3];
    ctx = InitCTX();
    cert_store =  X509_STORE_new ();
    ret = X509_STORE_load_locations(cert_store, "cacert.pem", 0);
    if (ret < 0)
    {
        printf("### Unable to set CA-cert ###");
	exit(0);
    }
    SSL_CTX_set_cert_store(ctx, cert_store);
    printf(" ### Certificates loaded X509 store ####");
    print_store_certs(BIO_new_fp(stdout,0), cert_store);

    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */

    server = OpenConnection(hostname, atoi(portnum));
    SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
#ifdef DEBUG
    SSL_set_msg_callback(ssl, SSL_trace);
    SSL_set_msg_callback_arg(ssl,BIO_new_fp(stdout,0));
#endif
    enable_hostname_verification(ssl, domain);
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "Client hello";
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   /* construct reply */
        printf("\n\nTLS Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
	SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
	while(1)
	{
		
		bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
		buf[bytes] = 0;
		if (bytes > 0)
		{
			printf("Received: \"%s\"\n", buf);
		}
	}
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
