#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include "rserve.h"

/* Utilities for working with raw byte arrays */

int set_hdr(int32_t type, int32_t len, char *y, size_t o)
{
  *(y + o) = (type & 0xff) | (len > 0xfffff0 ? DT_LARGE : 0);
  *(y + ++o) = len & 0xff;
  *(y + ++o) = (len & 0xff00) >> 8;
  *(y + ++o) = (len & 0xff0000) >> 16;
  if (len > 0xfffff0) {
    *(y + ++o) = (len & 0xff000000) >> 24;
    *(y + ++o) = 0;
    *(y + ++o) = 0;
    *(y + ++o) = 0;
  }
  return o;
}

int get_len(const char *y, size_t o)
{
  return (*(y + o) & 0x40) > 0
    ?
    (*(y + o + 1) & 0xff) |
    (*(y + o + 2) & 0xff) << 8 |
    (*(y + o + 3) & 0xff) << 16 |
    (*(y + o + 4) & 0xff) << 24
    :
    (*(y + o + 1) & 0xff) |
    (*(y + o + 2) & 0xff) << 8 |
    (*(y + o + 3) & 0xff) << 16;
}

void set_int(int32_t x, char *y, size_t o)
{
  *(y + o) = x & 0xff;
  *(y + ++o) = (x & 0xff00) >> 8;
  *(y + ++o) = (x & 0xff0000) >> 16;
  *(y + ++o) = (x & 0xff000000) >> 24;
}

int get_int(const char *y, size_t o)
{
  return (*(y + o) & 0xff) |
    (*(y + o + 1) & 0xff) << 8 |
    (*(y + o + 2) & 0xff) << 16 |
    (*(y + o + 3) & 0xff) << 24;
}

void set_long(int64_t x, char *y, size_t o)
{
  set_int((int)(x & 0xffffffffL), y, o);
  set_int((int)(x >> 32), y, o + 4);
}

long get_long(const char *y, size_t o)
{
  long low = ((long)get_int(y, o)) & 0xffffffffL;
  long hi = (((long)get_int(y, o + 4)) & 0xffffffffL) << 32;
  return hi |= low;
}

/* RPacket type for sending and receiving data from Rserve */

typedef struct
{
  RsrvCmd cmd;
  int size;
  char *data;
} RPacket;

void rpacket_clear(RPacket *rp)
{
  assert(rp != NULL);

  if (rp->data != NULL) free(rp->data);
}

/*
bool rpacket_is_oob(RPacket *rp)
{
  return false;
}
*/

bool rpacket_is_ok(RPacket *rp)
{
  if (rp == NULL) {
    return false;
  } else {
    return (rp->cmd & 15) == 1;
  }
}

bool rpacket_is_err(RPacket *rp)
{ 
  if (rp == NULL) {
    return true;
  } else {
    return (rp->cmd & 15) == 2;
  }
}

int rpacket_get_status(RPacket *rp)
{
  if (rp == NULL) {
    return -1;
  } else {
    return (rp->cmd >> 24) & 127;
  }
}

char *rpacket_to_str(char *s, size_t n, RPacket *rp)
{
  if (rp == NULL) {
    snprintf(s, n, "RPacket[]");
  } else {
    snprintf(s, n, "RPacket[cmd=%#08x,len=%d]", rp->cmd, rp->size);
  }
  return s;
}

/* Rserve client interface */

typedef struct
{
  int size;
  char *data;
} Buffer;

int response_hdr(const RConnection *conn, Buffer *hdr, RPacket* rp) 
{
  int n;
  bool own_header = false;
  char *data = malloc(16);

  if (hdr == NULL) {
    hdr = malloc(sizeof(Buffer));
    hdr->data = data;
    hdr->size = 16;
    own_header = true;
    errno = 0;
    if ((n = read(conn->sockfd, hdr->data, hdr->size)) != 16) {
      if (n < 0) {
        fprintf(stderr, "ERROR: while reading header, %s\n", strerror(errno));
      }
      fprintf(stderr, "ERROR: while reading header\n");
      return ERR_READ_SCKT;
    }
  }

  rp->cmd = get_int(hdr->data, 0);
  rp->size = get_int(hdr->data, 4);

  if (rp->size > 0) {
    errno = 0;
    n = 0;
    if ((rp->data = malloc(rp->size)) == NULL) {
      fprintf(stderr, "ERROR: while reading content, %s\n", strerror(errno));
      return ERR_READ_SCKT;
    }
    if (hdr->size > 16) {
      n = hdr->size - 16;
      memcpy(rp->data, hdr->data + 16, n);
    }
    while (n < rp->size) {
      errno = 0;
      if ((n += read(conn->sockfd, rp->data + n, rp->size - n)) < 0) {
        fprintf(stderr, "ERROR: while reading content, %s\n", strerror(errno));
        return ERR_READ_SCKT;
      }
    }
  }

  if (own_header) free(hdr);
  free(data);

  return 0;
}

int response(const RConnection *conn, RPacket *rp) 
{
  return response_hdr(conn, NULL, rp);
}

int request(const RConnection *conn, int cmd, Buffer *prefix, Buffer *cont, int offset,
    int len, RPacket *rp)
{
  int contlen;
  char hdr[16] = { 0 };

  if (cont != NULL) {
    if (offset >= cont->size) {
      cont = NULL;
      len = 0;
    } else if (len > cont->size - offset) {
      len = cont->size - offset;
    }
  }
  if (offset < 0) offset = 0;
  if (len < 0) len = 0;
  contlen = (cont == NULL) ? 0 : len;
  if (prefix != NULL && prefix->size > 0) contlen += prefix->size;

  set_int(cmd, hdr, 0);
  set_int(contlen, hdr, 4);

  if (cmd != -1) {
    if (write(conn->sockfd, hdr, sizeof(hdr)) < 0) {
      fprintf(stderr, "ERROR: Request, failed to write header\n");
      return ERR_READ_SCKT;
    }
    if (prefix != NULL && prefix->size > 0) {
      if (write(conn->sockfd, cont->data + offset, len) < 0) {
        fprintf(stderr, "ERROR: Request, failed to write prefix\n");
        return ERR_READ_SCKT;
      }
    }
    if (cont != NULL && cont->size > 0) {
      if (write(conn->sockfd, cont->data + offset, len) < 0) {
        fprintf(stderr, "ERROR: Request, failed to write content\n");
        return ERR_READ_SCKT;
      }
    }
  }
  
  return response(conn, rp);
}

int request_bytes(const RConnection *conn, int cmd, Buffer *cont, RPacket *rp)
{
  return request(conn, cmd, NULL, cont, 0, (cont == NULL) ? 0 : cont->size, rp);
}

int request_cmd(const RConnection *conn, int cmd, RPacket *rp)
{
  return request_bytes(conn, cmd, NULL, rp);
}

int request_string(const RConnection *conn, int cmd, const char *x, RPacket *rp)
{
  int sl, ret;
  Buffer rq = { 0 };

  sl = strlen(x) + 1;
  if ((sl & 3) > 0) sl = (sl & 0xfffffc) + 4;

  rq.size = sl + 5;

  //FIXME: ErrNo
  rq.data = calloc(rq.size, sizeof(char));
  memcpy(rq.data + 4, x, strlen(x));
  
  set_hdr(DT_STRING, sl, rq.data, 0);

  ret = request_bytes(conn, cmd, &rq, rp);

  free(rq.data);

  return ret;
}

int request_rexp(const RConnection *conn, int cmd, const REXP *rx, RPacket *rp)
{
  int rl, ret;
  Buffer rq = { 0 };

  if ((rl = rexp_binlen(rx)) < 0) {
    fprintf(stderr, "ERROR: while encoding, failed to get binary length\n");
    return ERR_ENCODE;
  }

  rq.size = rl + ((rl > 0xfffff0) ? 8 : 4);

  //FIXME: ErrNo
  rq.data = calloc(rq.size, sizeof(char));

  set_hdr(DT_SEXP, rl, rq.data, 0);

  if (rexp_encode(rx, rq.data, rq.size - rl, rl) < 0) {
    fprintf(stderr, "ERROR: while encoding, failed to get binary representation\n");
    free(rq.data);
    return ERR_ENCODE;
  }

  ret = request_bytes(conn, cmd, &rq, rp);

  free(rq.data);

  return ret;
}

int parse_response(RPacket *rp, REXP *rx)
{
  int rxo = 0;

  if (*rp->data != DT_SEXP && *rp->data != (DT_SEXP | DT_LARGE)) {
    fprintf(stderr, "ERROR: while parsing, incorrect data type returned by server\n");
    return ERR_DECODE;
  }

  if (*rp->data == (DT_SEXP | DT_LARGE)) rxo = 8; else rxo = 4;

  if (rp->size <= rxo) {
    fprintf(stderr, "ERROR: while parsing, packet size mismatch\n");
    return ERR_DECODE;
  }

  return rexp_decode(rx, rp->data, rxo) > 0 ? 0 : ERR_DECODE;
}

int init_ocap(RConnection *conn, Buffer *hdr)
{
  /* there is no version in OCAP but 103 is assumed since that is
	 * the earliest version that supports OCAPs
   * */
  conn->rsrv_ver = 103;
  conn->is_ocap = true;
  conn->connected = true;
  conn->capabilities = (REXP) { XT_NULL, NULL, NULL};

  int ret = 0;
  RPacket rp = { 0 };

  if ((ret = response_hdr(conn, hdr, &rp)) != 0) return ret;
  if ((ret = parse_response(&rp, &conn->capabilities)) != 0) return ret;

  rpacket_clear(&rp);

  fprintf(stderr, "INFO: successfully initialised OCAP\n");

  return ret;
}

int rserve_connect(RConnection *conn, const char *host, const int port)
{
  assert(strlen(host) > 0);
  assert(port > 0);

  const int attrlen = 4;
	int ret, n = 0;
	char ids[32] = { 0 }, attr[5] = { 0 };
	struct sockaddr_in serv_addr;

  conn->host = host;
  conn->port = port;
  conn->sockfd = -1;
  conn->connected = false;
  conn->auth_req = false;
  conn->plaintext = false;
  conn->is_ocap = false;
  conn->rsrv_ver = 0;
  conn->capabilities = (REXP) { XT_NULL, NULL, NULL};

  errno = 0;

	if ((conn->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "ERROR: creating socket, %s\n", strerror(errno));
		return ERR_CONN;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(conn->port);

	if ((ret = inet_pton(AF_INET, conn->host, &serv_addr.sin_addr)) < 0) {
    fprintf(stderr, "ERROR: invalid address family, %s\n", strerror(errno));
		return ERR_CONN;
	} else if (ret == 0) {
    fprintf(stderr, "ERROR: host string not valid\n");
		return ERR_CONN;
  }

	if (connect(conn->sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    fprintf(stderr, "ERROR: connecting socket, %s\n", strerror(errno));
		return ERR_CONN;
	} else {
    conn->connected = true;
  }

	if ((n = read(conn->sockfd, ids, sizeof(ids))) < 0) {
    fprintf(stderr, "ERROR: reading from socket, %s\n", strerror(errno));
    rserve_disconnect(conn);
    return ERR_CONN;
	}

  memcpy(attr, ids, attrlen);

  if (n >= 16 && strcmp(attr, "RsOC") == 0) {
    bool own_data = false;
    Buffer header = { 0 };
    header.size = n;
    /* It is possible that the buffering doesn't work out
     * and the first packet is < 32 bytes, in which case
     * we have to re-wrap the array to have the correct length
     * */
    if (n < 32) {
      header.data = malloc(n);
      own_data = true;
      memcpy(header.data, ids, n);
    } else {
      header.data = ids;
    }
    ret = init_ocap(conn, &header);
    if (own_data) free(header.data);
    return ret; //FIXME: What about auth below?
  }
  
  if (n != 32) {
    fprintf(stderr, "ERROR: handshake failed, expected 32 bytes header\n");
    rserve_disconnect(conn);
    return ERR_HSHK_FAILED;
  }

  if (strcmp(attr, "Rsrv") != 0) {
    fprintf(stderr, "ERROR: handshake failed, Rsrv signature expected\n");
    rserve_disconnect(conn);
    return ERR_HSHK_FAILED;
  }

  memcpy(attr, ids + 4, attrlen);
  conn->rsrv_ver = atoi(attr);

  if (conn->rsrv_ver != 103) {
    fprintf(stderr, "ERROR: handshake failed, client/server protocol mismatch\n");
    rserve_disconnect(conn);
    return ERR_HSHK_FAILED;
  }

  memcpy(attr, ids + 8, attrlen);

  if (strcmp(attr, "QAP1") != 0) {
    fprintf(stderr, "ERROR: handshake failed, unupported transfer protocol\n");
    rserve_disconnect(conn);
    return ERR_HSHK_FAILED;
  }

  for (int i = 12; i < 32; i += 4) {
    memcpy(attr, ids + i, attrlen);
    if (strcmp(attr, "ARpt") == 0) {
      conn->auth_req = true;
      conn->plaintext = true;
    }
    if (strcmp(attr, "ARuc") == 0) {
      conn->auth_req = true;
    }
  }

  if (conn->auth_req && !conn->plaintext) {
    fprintf(stderr, "WARN: encrypted auth not supported\n");
  }

  fprintf(stderr, "INFO: successfully connected to Rserve\n");

  return 0;
}

int rserve_disconnect(RConnection* conn)
{
  assert(conn != NULL);

  int ret = 0;

  if (conn->is_ocap) rexp_clear(&conn->capabilities);

  fprintf(stderr, "INFO: disconnecting from server\n");

  conn->connected = false;
  errno = 0; //FIXME: check errno?

  if ((ret = shutdown(conn->sockfd, 2)) != 0 ) {
    fprintf(stderr, "ERROR: while disconnecting, %s\n", strerror(errno));
  }

  return ret;
}

int rserve_login(const RConnection *conn, const char *user, const char *pwd)
{
  char *cred = calloc(strlen(user) + strlen(pwd) + 2, sizeof(char));
  RPacket rp = { 0 };

  if (!conn->connected) {
    fprintf(stderr, "ERROR: Login failed, not connected\n");
    return ERR_CONN;
  }

  if (!conn->auth_req) return 0;

  strcat(cred, user);
  strcat(cred, "\n");
  strcat(cred, pwd);

  request_string(conn, CMD_LOGIN, cred, &rp);

  if (!rpacket_is_ok(&rp)) {
    int ret = rpacket_get_status(&rp);
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: Login failed, unable to process server response\n");
    return ret;
  }

  rpacket_clear(&rp);
  free(cred);

  fprintf(stderr, "INFO: Login success, logged in to Rserve\n");

  return 0;
}

int rserve_eval(const RConnection *conn, const char *src, REXP *rx)
{
  assert(conn != NULL);
  assert(conn->connected);
  assert(rx != NULL);

  if (!conn->connected) {
    fprintf(stderr, "ERROR: during eval, not connected\n");
    return ERR_DISCONNECTED;
  }

  int ret = 0;
  RPacket rp = { 0 }; 

  if ((ret = request_string(conn, CMD_EVAL, src, &rp)) != 0) {
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: during eval, request failed\n");
    return ret;
  }

  if (!rpacket_is_ok(&rp)) {
    ret = rpacket_get_status(&rp);
    fprintf(stderr, "ERROR: during eval, server returned error\n");
    rpacket_clear(&rp);
    return ret;
  }

  if ((ret = parse_response(&rp, rx)) != 0) {
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: during eval, unable to parse response\n");
    return ret;
  }

  rpacket_clear(&rp);

  return ret;
}

int rserve_callocap(const RConnection *conn, const REXP *ocap, REXP *rx)
{
  assert(conn);
  assert(ocap);
  assert(rx);
  assert(conn->connected);
  assert(conn->is_ocap);

  int ret = 0;
  RPacket rp = { 0 }; 

  if ((ret = request_rexp(conn, CMD_OCCALL, ocap, &rp)) != 0) {
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: during callocap, request failed\n");
    return ret;
  }

  if (!rpacket_is_ok(&rp)) {
    ret = rpacket_get_status(&rp);
    //FIXME: get the type of error from the RPacket?
    fprintf(stderr, "ERROR: during callocap server returned error\n");
    rpacket_clear(&rp);
    return ret;
  }

  if ((ret = parse_response(&rp, rx)) != 0) {
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: during eval, unable to parse response\n");
    return ret;
  }

  rpacket_clear(&rp);

  return ret;
}

int rserve_assign(const RConnection *conn, const char *sym, const REXP *rx)
{
  assert(conn);
  assert(sym);
  assert(rx);
  assert(conn->connected);

  int sl, rl, ret;
  Buffer rq =  { 0 };
  RPacket rp = { 0 }; 

  sl = strlen(sym) + 1;
  // make sure the symbol length is divisible by 4
  if ((sl & 3) > 0) sl = (sl & 0xfffffc) + 4; 

  if ((rl = rexp_binlen(rx)) < 0) {
    fprintf(stderr, "ERROR: while encoding, failed to get binary length\n");
    return ERR_ENCODE;
  }

  rq.size = sl + rl + ((rl > 0xfffff0) ? 12 : 8);

  if ((rq.data = calloc(rq.size, sizeof(char))) == NULL) {
    fprintf(stderr, "ERROR: while encoding, failed to alloc request\n");
    //ErrNo?
    return ERR_ENCODE;
  }

  set_hdr(DT_STRING, sl, rq.data, 0);

  for (size_t i  = 0; i <  strlen(sym); ++i) rq.data[i + 4] = sym[i];

  set_hdr(DT_SEXP, rl, rq.data, sl + 4);

  if ((ret = rexp_encode(rx, rq.data, rq.size - rl, rl)) < 0) {
    fprintf(stderr, "ERROR: while encoding, failed to get binary representation\n");
    free(rq.data);
    return ret;
  }

  if ((ret = request_bytes(conn, CMD_SETSEXP, &rq, &rp)) != 0) {
    rpacket_clear(&rp);
    free(rq.data);
    fprintf(stderr, "ERROR: during assign, request failed\n");
    return ret;
  }

  if (!rpacket_is_ok(&rp)) {
    ret = rpacket_get_status(&rp);
    //FIXME: get the type of error from the RPacket?
    fprintf(stderr, "ERROR: during assign server returned error\n");
    free(rq.data);
    rpacket_clear(&rp);
    return ret;
  }

  free(rq.data);
  rpacket_clear(&rp);

  return ret;
}

int rserve_shutdown(RConnection *conn)
{
  assert(conn);
  assert(conn->connected);

  int ret = 0;
  RPacket rp = { 0 }; 

  if ((ret = request_cmd(conn, CMD_SHUTDOWN, &rp)) != 0) {
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: during shutdown, request failed\n");
    return ret;
  }

  if (!rpacket_is_ok(&rp)) {
    ret = rpacket_get_status(&rp);
    //FIXME: get the type of error from the RPacket?
    fprintf(stderr, "ERROR: during shutdown, server returned error\n");
    rpacket_clear(&rp);
    return ret;
  }

  //FIXME: disconnect?

  rpacket_clear(&rp);

  return ret;
}

char *rserve_error(int err)
{
  switch (err) {
    case ERR_CONN:
      return "Client error connecting to Rserve";
    case ERR_HSHK_FAILED:
      return "Client failed to successfully complete handshake with Rserve";
    case ERR_DISCONNECTED:
      return "Client not connected to an Rserve instance";
    case ERR_READ_SCKT:
      return "Client failed to read from Rserve";
    case ERR_DECODE:
      return "Client failed to decode Rserve response";
    case ERR_ENCODE:
      return "Client failed to encode Rserve request";
    default:
      return "Unknown error";
  }
}
