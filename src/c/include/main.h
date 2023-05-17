#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509v3.h>

typedef struct {
    void *buf;
    int len;
    int offset;
} TLSData;

typedef struct TLSDataNode_t {
    TLSData data;
    struct TLSDataNode_t *prev;
} TLSDataNODE;

/* the HEAD of the Queue, hold the amount of node's that are in the queue*/
typedef struct TLSDataQueue {
    TLSDataNODE *head;
    TLSDataNODE *tail;
    int size;
    int limit;
    int fd;
} TLSDataQueue;

TLSDataQueue *constructTLSDataQueue(int fd, int limit);
void destructTLSDataQueue(TLSDataQueue *queue);
int enqueueTLSData(TLSDataQueue *pQueue, void *buf, int len );
TLSDataNODE *dequeueTLSData(TLSDataQueue *pQueue);
TLSDataNODE *peekTLSData(TLSDataQueue *pQueue);
int isEmptyTLSData(TLSDataQueue* pQueue);

typedef struct fd_kv_t_struct {
    int                     fd;
    TLSDataQueue            *tlsDataQueue;
    struct fd_kv_t_struct   *next;
} fd_kv_t;

void fd_kv_alloc(void);
TLSDataQueue *fd_kv_getItem(int fd);
void fd_kv_delItem(int fd);
void fd_kv_addItem(int fd, TLSDataQueue *tlsDataQueue);


#define TRUE  1
#define FALSE	0


struct keystruct
{
    EVP_PKEY *evp_keyobject;
    int NID;
    int outtype;
    bool EVP_ONLY;
    EC_GROUP *ecgroup;
    int compressed;
    char *password;
    int error;
};

struct keystruct hexToEVP(char *hex_private, int NID, int outtype, int compressed, char *password);

char *trim_space(char *str);

int throwError();

uint8_t *createBuffer(int bsize);

void destroyBuffer(uint8_t *p);

char *toLower(char *str);

char *toUpper(char *str);

X509_NAME *str2Name(int namePointer, X509_NAME *name);

int set_genString(GENERAL_NAMES *gens, int NID, char *value);

int cleanup();