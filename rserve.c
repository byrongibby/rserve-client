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

int set_hdr(int32_t type, int32_t len, char* y, size_t o)
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

char* new_hdr(int32_t type, int32_t len)
{
  char *hdr = malloc(len > 0xfffff0 ? 8 : 4);
  set_hdr(type, len, hdr, 0);
  return hdr;
}

int get_len(char* y, size_t o)
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

void set_int(int32_t x, char* y, size_t o)
{
  *(y + o) = x & 0xff;
  *(y + ++o) = (x & 0xff00) >> 8;
  *(y + ++o) = (x & 0xff0000) >> 16;
  *(y + ++o) = (x & 0xff000000) >> 24;
}

int get_int(char* y, size_t o)
{
  return (*(y + o) & 0xff) |
    (*(y + o + 1) & 0xff) << 8 |
    (*(y + o + 2) & 0xff) << 16 |
    (*(y + o + 3) & 0xff) << 24;
}

void set_long(int64_t x, char* y, size_t o)
{
  set_int((int)(x & 0xffffffffL), y, o);
  set_int((int)(x >> 32), y, o + 4);
}

long get_long(char* y, size_t o)
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

int rserve_connect(RConnection *conn, char *host, int port)
{
  assert(strlen(host) > 0);
  assert(port > 0);

  const int attrlen = 4;
	int ret, n = 0;
	char ids[32], attr[5] = { 0 };
	struct sockaddr_in serv_addr;

  conn->host = host;
  conn->port = port;
  conn->sockfd = -1;
  conn->connected = false;
  conn->auth_req = false;
  conn->plaintext = false;
  conn->rsrv_ver = 0;

  errno = 0;

	if ((conn->sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "ERROR: creating socket: %s\n", strerror(errno));
		return CONN_ERR;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(conn->port);

	if ((ret = inet_pton(AF_INET, conn->host, &serv_addr.sin_addr)) < 0) {
    fprintf(stderr, "ERROR: invalid address family: %s\n", strerror(errno));
		return CONN_ERR;
	} else if (ret == 0) {
    fprintf(stderr, "ERROR: host string not valid\n");
		return CONN_ERR;
  }

	if (connect(conn->sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    fprintf(stderr, "ERROR: connecting socket: %s\n", strerror(errno));
		return CONN_ERR;
	} else {
    conn->connected = true;
  }

	memset(ids, 0, sizeof(ids));

	if ((n = read(conn->sockfd, ids, sizeof(ids))) < 0) {
    fprintf(stderr, "ERROR: reading from socket: %s\n", strerror(errno));
    rserve_disconnect(conn);
    return CONN_ERR;
	}

  if (n != 32) {
    fprintf(stderr, "ERROR: handshake failed: expected 32 bytes header\n");
    rserve_disconnect(conn);
    return HSHK_FAILED;
  }

  memcpy(attr, ids, attrlen);

  if (n >= 16 && strcmp(attr, "RsOC") == 0) {
    fprintf(stderr, "ERROR: handshake failed: OCAP mode not supported\n");
    rserve_disconnect(conn);
    return HSHK_FAILED;
  }
  
  if (strcmp(attr, "Rsrv") != 0) {
    fprintf(stderr, "ERROR: handshake failed: Rsrv signature expected\n");
    rserve_disconnect(conn);
    return HSHK_FAILED;
  }

  memcpy(attr, ids + 4, attrlen);
  conn->rsrv_ver = atoi(attr);

  if (conn->rsrv_ver != 103) {
    fprintf(stderr, "ERROR: handshake failed: client/server protocol mismatch\n");
    rserve_disconnect(conn);
    return HSHK_FAILED;
  }

  memcpy(attr, ids + 8, attrlen);

  if (strcmp(attr, "QAP1") != 0) {
    fprintf(stderr, "ERROR: handshake failed: unupported transfer protocol\n");
    rserve_disconnect(conn);
    return HSHK_FAILED;
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

  int ret;

  fprintf(stderr, "INFO: disconnecting from server\n");

  conn->connected = false;
  errno = 0;

  if ((ret = shutdown(conn->sockfd, 2)) != 0 ) {
    fprintf(stderr, "ERROR: while disconnecting: %s\n", strerror(errno));
    return ret;
  }

  return 0;
}

typedef struct
{
  char *data;
  int size;
} Buffer;

int response_hdr(RConnection *conn, Buffer *hdr, RPacket* rp) 
{
  int n;
  char data[16];

  if (hdr == NULL) {
    hdr = &(Buffer) { .data = data, .size = sizeof(data) };
    errno = 0;
    if ((n = read(conn->sockfd, hdr->data, hdr->size)) != 16) {
      if (n < 0) {
        fprintf(stderr, "ERROR: while reading header: %s\n", strerror(errno));
      }
      fprintf(stderr, "ERROR: while reading header\n");
      return READ_ERR;
    }
  }

  rp->cmd = get_int(hdr->data, 0);
  rp->size = get_int(hdr->data, 4);

  if (rp->size > 0) {
    errno = 0;
    n = 0;
    if ((rp->data = malloc(rp->size)) == NULL) {
      fprintf(stderr, "ERROR: while reading content: %s\n", strerror(errno));
      return READ_ERR;
    }
    if (hdr->size > 16) {
      n = hdr->size - 16;
      memcpy(rp->data, hdr->data + 16, n);
    }
    while (n < rp->size) {
      errno = 0;
      if ((n += read(conn->sockfd, rp->data + n, rp->size - n)) < 0) {
        fprintf(stderr, "ERROR: while reading content: %s\n", strerror(errno));
        return READ_ERR;
      }
    }
  }

  return 0;
}

int response(RConnection *conn, RPacket *rp) 
{
  return response_hdr(conn, NULL, rp);
}

int request(RConnection* conn, int cmd, Buffer *prefix, Buffer *cont, int offset,
    int len, RPacket *rp)
{
  int contlen;
  char hdr[16];

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

	memset(hdr, 0, sizeof(hdr));
  set_int(cmd, hdr, 0);
  set_int(contlen, hdr, 4);

  if (cmd != -1) {
    if (write(conn->sockfd, hdr, sizeof(hdr)) < 0) {
      fprintf(stderr, "ERROR: Request: Failed to write header\n");
      return READ_ERR;
    }
    if (prefix != NULL && prefix->size > 0) {
      if (write(conn->sockfd, cont->data + offset, len) < 0) {
        fprintf(stderr, "ERROR: Request: Failed to write prefix\n");
        return READ_ERR;
      }
    }
    if (cont != NULL && cont->size > 0) {
      if (write(conn->sockfd, cont->data + offset, len) < 0) {
        fprintf(stderr, "ERROR: Request: Failed to write content\n");
        return READ_ERR;
      }
    }
  }
  
  return response(conn, rp);
}

int request_bytes(RConnection *conn, int cmd, Buffer *cont, int len, RPacket *rp)
{
  return request(conn, cmd, NULL, cont, 0, (cont == NULL) ? 0 : len, rp);
}

int request_cmd(RConnection *conn, int cmd, RPacket *rp)
{
  return request_bytes(conn, cmd, NULL, 0, rp);
}

int request_string(RConnection *conn, int cmd, char* x, RPacket *rp)
{
  int sl = strlen(x) + 1;
  if ((sl & 3) > 0) sl = (sl & 0xfffffc) + 4;

  char rq[sl + 5];
	memset(rq, 0, sizeof(rq));
  memcpy(rq + 4, x, strlen(x));

  set_hdr(DT_STRING, sl, rq, 0);
  Buffer *cont = &(Buffer) { .data = rq, .size = sizeof(rq) };
  
  return request_bytes(conn, cmd, cont, cont->size, rp);
}

/* RPacket *request_rexp(RConnection *conn, int cmd, REXPContainer x); */
/* RPacket *request_int(RConnection *conn, int cmd, int x); */

int rserve_login(RConnection *conn, char *user, char *pwd)
{
  char cred[strlen(user) + strlen(pwd) + 2];
  RPacket rp = { 0, 0, NULL };

  if (!conn->connected) {
    fprintf(stderr, "ERROR: Login failed: Not connected\n");
    return CONN_ERR;
  }

  if (!conn->auth_req) return 0;

	memset(&cred, 0, sizeof(cred));

  strcat(cred, user);
  strcat(cred, "\n");
  strcat(cred, pwd);

  request_string(conn, LOGIN, cred, &rp);

  if (!rpacket_is_ok(&rp)) {
    int ret = rpacket_get_status(&rp);
    rpacket_clear(&rp);
    fprintf(stderr, "ERROR: Login failed: Unable to process server response\n");
    return ret;
  }

  rpacket_clear(&rp);

  fprintf(stderr, "INFO: Login success: Logged in to Rserve\n");

  return 0;
}

int parse_response(RPacket *rp, REXP *rx)
{
  int rxo = 0;

  if (*rp->data != DT_SEXP && *rp->data != (DT_SEXP | DT_LARGE)) {
    fprintf(stderr, "ERROR: while parsing, incorrect data type returned by server\n");
    return PARSE_ERR;
  }

  if (*rp->data == (DT_SEXP | DT_LARGE)) rxo = 8; else rxo = 4;

  if (rp->size <= rxo) {
    fprintf(stderr, "ERROR: while parsing, packet size mismatch\n");
    return PARSE_ERR;
  }

  rexp_parse(rx, rp->data, rxo);

  return 0;
}

int rserve_eval(RConnection *conn, char *cmd, REXP *rx)
{
  assert(conn != NULL);
  assert(conn->connected);
  assert(rx != NULL);

  if (!conn->connected) {
    fprintf(stderr, "ERROR: during eval, not connected\n");
    return DISCONNECTED;
  }

  int ret;
  RPacket rp; 

  if ((ret = request_string(conn, EVAL, cmd, &rp)) != 0) {
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

/*
int rserve_assign()
{

}

int rserve_shutdown()
{

}
*/

const char *rserve_error(int err)
{
  switch (err) {
    case CONN_ERR:
      return "Client error connecting to Rserve";
    case HSHK_FAILED:
      return "Client failed to successfully complete handshake with Rserve";
    case DISCONNECTED:
      return "Client not connected to an Rserve instance";
    case READ_ERR:
      return "Client failed to read from Rserve";
    case PARSE_ERR:
      return "Client failed to parse Rserve response";
    default:
      return "Unknown error";
  }
}
