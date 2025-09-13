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
  CONN_ERR     = 0x30,
  HSHK_FAILED  = 0x31,
  DISCONNECTED = 0x32,
  READ_ERR     = 0x33,
  DECODE_ERR   = 0x34,
  ENCODE_ERR   = 0x35,
} RsrvClientError;

typedef enum {
  AUTH_FAILED     = 0x41,
  CONN_BROKEN     = 0x42,
  INV_CMD         = 0x43,
  INV_PAR         = 0x44,
  RERROR          = 0x45,
  IOERROR         = 0x46,
  NOT_OPEN        = 0x47,
  ACCESS_DENIED   = 0x48,
  UNSUPPORTED_CMD = 0x49,
  UNKNOWN_CMD     = 0x4a,
  DATA_OVERFLOW   = 0x4b,
  OBJECT_TOO_BIG  = 0x4c,
  OUT_OF_MEM      = 0x4d,
  CTRL_CLOSED     = 0x4e,
  SESSION_BUSY    = 0x50,
  DETACH_FAILED   = 0x51,
  DISABLED        = 0x61,
  UNAVAILABLE     = 0x62,
  CRYPTERROR      = 0x63,
  SECURITYCLOSE   = 0x64,
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
  char *host;
  int port;
  int sockfd;
  bool connected;
  bool auth_req;
  bool plaintext;
  int rsrv_ver;
  bool is_ocap;
  REXP capabilities;
} RConnection;

int rserve_connect(RConnection *conn, char *host, int port);
int rserve_disconnect(RConnection* conn);
int rserve_login(RConnection *conn, char *user, char *pwd);
int rserve_eval(RConnection *conn, char *cmd, REXP *rx);
int rserve_callocap(RConnection *conn, REXP *ocap, REXP *rx);
int rserve_assign(RConnection *conn, char *sym, REXP *rx);
int rserve_shutdown(RConnection *conn);
const char *rserve_error(int err);

#endif /* RSERVE_H_ */
