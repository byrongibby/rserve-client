#ifndef RSERVE_H_ 
#define RSERVE_H_

#include "rexp.h"

typedef enum {
  DT_INT        = 1,
  DT_CHAR       = 2,
  DT_DOUBLE     = 3,
  DT_STRING     = 4,
  DT_BYTESTREAM = 5,
  DT_SEXP       = 10,
  DT_ARRAY      = 11,
  DT_CUSTOM     = 32,
  DT_LARGE      = 64,
} RsrvDataType;

typedef enum {
  ERR_CONN         = 0x30,
  ERR_HSHK_FAILED  = 0x31,
  ERR_DISCONNECTED = 0x32,
  ERR_READ_SCKT    = 0x33,
  ERR_DECODE       = 0x34,
  ERR_ENCODE       = 0x35,
} RsrvClientError;

typedef enum {
  ERR_AUTH_FAILED     = 0x41,
  ERR_CONN_BROKEN     = 0x42,
  ERR_INV_CMD         = 0x43,
  ERR_INV_PAR         = 0x44,
  ERR_RERROR          = 0x45,
  ERR_IOERROR         = 0x46,
  ERR_NOT_OPEN        = 0x47,
  ERR_ACCESS_DENIED   = 0x48,
  ERR_UNSUPPORTED_CMD = 0x49,
  ERR_UNKNOWN_CMD     = 0x4a,
  ERR_DATA_OVERFLOW   = 0x4b,
  ERR_OBJECT_TOO_BIG  = 0x4c,
  ERR_OUT_OF_MEM      = 0x4d,
  ERR_CTRL_CLOSED     = 0x4e,
  ERR_SESSION_BUSY    = 0x50,
  ERR_DETACH_FAILED   = 0x51,
  ERR_DISABLED        = 0x61,
  ERR_UNAVAILABLE     = 0x62,
  ERR_CRYPTERROR      = 0x63,
  ERR_SECURITYCLOSE   = 0x64,
} RsrvServerError;

typedef enum {
  CMD_LOGIN         = 0x001,
  CMD_VOIDEVAL      = 0x002,
  CMD_EVAL          = 0x003,
  CMD_SHUTDOWN      = 0x004,
  CMD_OCCALL        = 0x00f,
  CMD_SETSEXP       = 0x020,
  CMD_ASSIGNSEXP    = 0x021,
  CMD_SETBUFFERSIZE = 0x081,
  CMD_SETENCODING   = 0x082,
} RsrvCmd;

#define RESP_CMD 0x10000
#define RESP_OK  0x10001
#define RESP_ERR 0x10002

typedef struct {
  const char *host;
  int port;
  int sockfd;
  bool connected;
  bool auth_req;
  bool plaintext;
  int rsrv_ver;
  bool is_ocap;
  REXP capabilities;
} RConnection;

int rserve_connect(RConnection *conn, const char *host, int port);
int rserve_disconnect(RConnection* conn);
int rserve_login(const RConnection *conn, const char *user, const char *pwd);
int rserve_eval(const RConnection *conn, const char *src, REXP *rx);
int rserve_callocap(const RConnection *conn, const REXP *ocap, REXP *rx);
int rserve_assign(const RConnection *conn, const char *sym, const REXP *rx);
int rserve_shutdown(RConnection *conn);
char *rserve_error(int err);

#endif /* RSERVE_H_ */
