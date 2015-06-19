/*
 * main.c
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <pcre.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <openssl/ssl.h>

#include "globals.h"
#include "callback.h"

#define PACKAGE    "http_extend"
#define VERSION    "1.x"

#define MAX_CERTS 20

X509 *certificates[MAX_CERTS];
long certificates_error[MAX_CERTS];
CURLcode sslctxfunc(CURL *curl, void *sslctx, void *parm);
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
void print_certificate(X509 *cert);

static time_t ASN1_GetTimeT(ASN1_TIME* atime)
{
    struct tm t;
    const char* str = (const char*) atime->data;
    int i = 0;

    memset(&t, 0, sizeof(t));

    if (atime->type == V_ASN1_UTCTIME) {
        t.tm_year = ((str[i++]) - '0') * 10;
        t.tm_year += ((str[(i++)]) - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } else if (atime->type == V_ASN1_GENERALIZEDTIME) {
        t.tm_year =    (str[i++] - '0') * 1000;
        t.tm_year += (str[i++] - '0') * 100;
        t.tm_year += (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; /* -1 since January is 0 not 1. */
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday += (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour += (str[i++] - '0');
    t.tm_min    = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec    = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');
    /* Note: we did not adjust the time based on time zone information */
    return mktime(&t);
}

void print_help(int exval) {
    if (isatty(0) == 1) {
        fprintf(stderr,"%s,%s fetch http urls and extract values\n", PACKAGE, VERSION);
        fprintf(stderr,"%s [-?] [-V] [-v] [-u URL] [-r PCRE-REGEX]\n\n", PACKAGE);

        fprintf(stderr,"  -?              print this help and exit\n");
        fprintf(stderr,"  -V              print version and exit\n\n");
        fprintf(stderr,"  -v              set verbose flag (repeat for more output)\n");
        fprintf(stderr,"  -a              use the entire http/https response for contect parsing (i.e. headers)\n");
        fprintf(stderr,"  -l              follow location redirects\n");
        fprintf(stderr,"  -i              ignore ssl certificate verification\n");
        fprintf(stderr,"  -f              fail request on curl errors (receive buffer of %i bytes exceded, http-errors, ..)\n",MAX_BUF);
        fprintf(stderr,"  -s              provide only the status of the request (zabbix values: 1 = OK, 0 = NOT OK, )\n");
        fprintf(stderr,"  -m              provide the total delivery time of the request in seconds (zabbix values: >0.0 = OK (seconds), 0.0 = NOT OK)\n");
        fprintf(stderr,"  -c              check ssl certificate and return days until expire\n");
        fprintf(stderr,"  -u URL          Specify the url to fetch\n");
        fprintf(stderr,"  -t mseconds     Timeout of curl request in 1/1000 seconds (default: %i milliseconds)\n",TIMEOUT);
        fprintf(stderr,"  -r PCRE-REGEX   Specify the matching regex\n");
        fprintf(stderr,"  -M              set regex MULTILINE option\n");
        fprintf(stderr,"  -h HOSTNAME     Specify the host header\n\n");
    }
    exit(exval);
}

void print_arguments(int argc, char *argv[]) {
    int i;
    if (isatty(0) != 1) {
        fprintf(stderr,"ARGUMENTS: ");
        for (i = 0; i < argc; i++){
            fprintf(stderr,"%s ",argv[i]);
        }
        fprintf(stderr,"\n");
    }
}

/* Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff<0);
}



int main(int argc, char *argv[]) {

    CURL *curl;
    CURLcode ret;
    char *url = NULL;
    char *host_header = NULL;
    char *host_name = NULL;
    char *regex = NULL;

    struct timeval tvBegin, tvEnd, tvDiff;

    /* Commandline switches */
    int verbose_level=0;
    int status_only = false;
    int measure_time = false;
    int nossl_verify = false;
    int follow_location = false;
    int fail_on_curl_error = false;
    int ssl_valid_date = false;

    struct curl_slist *headers = NULL;
    int i;
    int curl_timeout = TIMEOUT;
    char *curl_userpwd = NULL;

    ASN1_TIME * notAfter;
    time_t now;
    time_t expire;
    int time_left;

    pcre *re;
    int pcre_opts=0;
    const char *error;
    int erroffset;
    int ovector[OVECCOUNT];
    int rc;
    int opt;

    wr_error = 0;
    wr_index = 0;

    /* First step, init curl */
    curl = curl_easy_init();
    if(!curl) {
        fprintf(stderr, "couldn't init curl\n");
        exit(EXIT_FAILURE);
    }

    /* 
     * if no arguments are given
     */
    if(argc == 1) {
        fprintf(stderr, "This program needs arguments....\n\n");
        print_arguments(argc, argv);
        print_help(1);
    }

    while((opt = getopt(argc, argv, "?VfcamMlsvp:t:u:h:r:i")) != -1) {
        switch(opt) {
            case 'V':
                fprintf(stderr,"%s %s\n\n", PACKAGE, VERSION);
                exit(0);
                break;
            case 'v':
                verbose_level++;
                break;
            case 'a':
                curl_easy_setopt(curl, CURLOPT_HEADER  , true);
                break;
            case 'i':
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
                nossl_verify = true;
                break;
            case 's':
                status_only = true;
                break;
            case 'm':
                measure_time = true;
                break;
            case 'M':
                pcre_opts |= PCRE_MULTILINE;
                break;
            case 'l':
                follow_location = true;
                curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);
                break;
            case 'f':
                fail_on_curl_error = true;
                break;
            case 'p':
                curl_userpwd = optarg;
                break;
            case 'u':
                url = optarg;
                break;
            case 't':
                curl_timeout = atoi(optarg);
                break;
            case 'h':
                host_header = malloc(strlen("Host: ") + strlen(optarg) + 1);
                host_name = optarg;
                strcpy(host_header, "Host: ");
                strcat(host_header, optarg);
                headers = curl_slist_append(headers, host_header);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                break;
            case 'c':
                ssl_valid_date = true;
            case 'r':
                regex = optarg;
                break;
            case ':':
                fprintf(stderr, "%s: Error - Option `%c' needs a value\n\n", PACKAGE, optopt);
                print_arguments(argc, argv);
                print_help(1);
                break;
            case '?':
                fprintf(stderr, "%s: Error - No such option: `%c'\n", PACKAGE, optopt);
                print_arguments(argc, argv);
                print_help(1);
        }
    }

    if (verbose_level > 3){
        curl_easy_setopt(curl, CURLOPT_VERBOSE , true);
    }

    if (verbose_level > 0){
        fprintf(stderr, "%-17s %s\n", "URL", url);
        fprintf(stderr, "%-17s %s\n", "REGEX", regex);
        fprintf(stderr, "%-17s %i\n", "TIMEOUT", curl_timeout);
        fprintf(stderr, "%-17s %s\n",   "HOST HEADER", host_header);
        fprintf(stderr, "%-17s %i\n\n", "STATUS ONLY", status_only);

        fprintf(stderr, "%-17s %s -t %i -u \"%s\" -r \"%s\"", "CMD ", PACKAGE, curl_timeout, url, regex);
        if ( status_only == true ){
            fprintf(stderr, " -s");
        }
        if ( measure_time  == true ){
            fprintf(stderr, " -m");
        }
        if ( nossl_verify == true ){
            fprintf(stderr, " -i");
             }
        if ( follow_location == true ){
            fprintf(stderr, " -l");
             }
        if ( fail_on_curl_error == true ){
            fprintf(stderr, " -f");
        }
        if ( (pcre_opts & PCRE_MULTILINE) == PCRE_MULTILINE ){
            fprintf(stderr, " -M");
        }
        if (curl_userpwd != NULL){
            fprintf(stderr, " -p %s", curl_userpwd);
        }

        if ( host_name != NULL ){
            fprintf(stderr, " -h %s",host_name);
        }
        fprintf(stderr, "\n");

        fprintf(stderr, "%-17s %s[\"-t\",\"%i\",\"-u\",\"%s\",\"-r\",\"%s\"", "ZABBIX 2.0 ITEM", PACKAGE, curl_timeout, url, regex);
        if ( status_only == true ){
            fprintf(stderr, ",\"-s\"");
        }
        if ( measure_time  == true ){
            fprintf(stderr, ",\"-m\"");
        }
        if ( nossl_verify == true ){
            fprintf(stderr, ",\"-i\"");
             }
        if ( follow_location == true ){
            fprintf(stderr, ",\"-l\"");
             }
        if ( fail_on_curl_error == true ){
            fprintf(stderr, ",\"-f\"");
        }
        if ( (pcre_opts & PCRE_MULTILINE) == PCRE_MULTILINE ){
            fprintf(stderr, ",\"-M\"");
        }
        if (curl_userpwd != NULL){
            fprintf(stderr, ",\"-p\",\"%s\"", curl_userpwd);
        }

        if ( host_name != NULL ){
            fprintf(stderr, ",\"-h\",\"%s\"",host_name);
        }
       fprintf(stderr, "]\n");
    }


    if (((url == NULL) || (regex == NULL)) && (ssl_valid_date == false)){
        print_arguments(argc, argv);
        print_help(EXIT_FAILURE);
    }

    /* Tell curl the URL of the file we're going to retrieve */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 GTB5");

    /* Tell curl that we'll receive data to the function write_data, and
     * also provide it with a context pointer for our error return.
     */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &wr_error);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, curl_timeout);

    curl_easy_setopt(curl, CURLOPT_USERPWD, curl_userpwd);

    gettimeofday(&tvBegin, NULL);
    /* Initialize certificate array*/
    for(i=0; i<MAX_CERTS;i++) {
        certificates[i] = 0;
        certificates_error[i] = X509_V_OK;
    }
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfunc);
    if(ssl_valid_date == true) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false);
    }

    /* Allow curl to perform the action */
    ret = curl_easy_perform(curl);
    /* Stop execution here if only status is needed */
    if ((ret != 0) || (fail_on_curl_error == true)){
        if (status_only == true){
            printf("0");
            if (verbose_level > 1){
                fprintf(stderr,"returned: '0'\n");
            }
        } else if (measure_time == true){
            printf("0.0");
            if (verbose_level > 1){
                fprintf(stderr,"returned: '0.0'\n");
            }
        }
        exit(EXIT_FAILURE);
    }

    /* Get days until certificate expires */
    if(ssl_valid_date == true) {
        if(ret!=0 || certificates[0]==0) {
            exit(EXIT_FAILURE);
        }
        notAfter = X509_get_notAfter(certificates[0]);
        now = time(NULL);
        expire = ASN1_GetTimeT(notAfter);
        time_left = (expire-now)/(60*60*24);

        printf("%d",time_left);

        if (verbose_level > 1){
            fprintf(stderr,"returned: '%d'\n",time_left);
        }

        curl_easy_cleanup(curl);
        exit(EXIT_SUCCESS);
    }

    re = pcre_compile(regex,    /* the pattern */
                      pcre_opts,        /* default options */
                      &error,   /* for error message */
                      &erroffset,   /* for error offset */
                      NULL);    /* use default character tables */


    rc = pcre_exec(re,          /* the compiled pattern */
                   NULL,        /* no extra data - we didn't study the pattern */
                   wr_buf,      /* the subject string */
                   wr_index,    /* the length of the subject */
                   0,           /* start at offset 0 in the subject */
                   0,           /* default options */
                   ovector,     /* output vector for substring information */
                   OVECCOUNT);  /* number of elements in the output vector */

    if(verbose_level > 2) {
        fprintf(stderr, "out: >>>%s<<< [%i bytes]\n", wr_buf, wr_index);
    }

    /* Evaluate the match and output status */
    if(rc < 0) {
        if (status_only == true) {
            printf("0");
            if (verbose_level > 1){
                fprintf(stderr,"returned: '0'\n");
            }
        } else if (measure_time == true) {
            printf("0.0");
            if (verbose_level > 1){
                fprintf(stderr,"returned: '0.0'\n");
            }
        } else {
            switch (rc) {
                case PCRE_ERROR_NOMATCH      : fprintf(stderr,"String did not match the pattern\n");        break;
                case PCRE_ERROR_NULL         : fprintf(stderr,"Something was null\n");                      break;
                case PCRE_ERROR_BADOPTION    : fprintf(stderr,"A bad option was passed\n");                 break;
                case PCRE_ERROR_BADMAGIC     : fprintf(stderr,"Magic number bad (compiled re corrupt?)\n"); break;
                case PCRE_ERROR_UNKNOWN_NODE : fprintf(stderr,"Something kooky in the compiled re\n");      break;
                case PCRE_ERROR_NOMEMORY     : fprintf(stderr,"Ran out of memory\n");                       break;
                default                      : fprintf(stderr,"Matching error %d\n", rc);                   break;
            }
        }
        pcre_free(re);          /* Release memory used for the compiled pattern */
        exit(EXIT_FAILURE);
    }

    if(rc == 2) {
        if (status_only == true) {
            printf("1");
            if (verbose_level > 1) {
                fprintf(stderr,"returned: '1'\n");
            }
        } else if (measure_time == true) {
            gettimeofday(&tvEnd, NULL);
            timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
            printf("%ld.%06ld", tvDiff.tv_sec, tvDiff.tv_usec);
            if (verbose_level > 1){
                fprintf(stderr,"measure time returned: '%ld.%06ld'\n", tvDiff.tv_sec, tvDiff.tv_usec);
            }
        } else {
            int n;
            int start_parse = ovector[2];
            int end_parse = ovector[3];
            fprintf(stderr, "parsing returned: ");
            for(n=start_parse; n<end_parse; n++) {
                putchar(wr_buf[n]);
                fprintf(stderr, "%c", wr_buf[n]);
            }
            fprintf(stderr, "\n"); 
        }
    }
    curl_easy_cleanup(curl);

    exit(EXIT_SUCCESS);
}

CURLcode sslctxfunc(CURL *curl, void *sslctx, void *parm) {
    (void)parm;
    if(!curl) {
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, verify_callback);
    return CURLE_OK;
}

/* Add certificate chain and errors to certs array */
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    if (depth < MAX_CERTS && !certificates[depth]) {
        certificates[depth] = cert;
        certificates_error[depth] = err;
        cert->references++;
    }
  (void) preverify_ok;
  return 1;
}

/* vim:ai et ts=2 shiftwidth=2 expandtab tabstop=3 tw=120 */
