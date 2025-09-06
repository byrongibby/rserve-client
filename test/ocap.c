#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rexp.h"
#include "rserve.h"

int main(void)
{
  int ret;
  RConnection conn = { 0 };
  REXP rx = { 0 };

  if ((ret = rserve_connect(&conn, "127.0.0.1", 6311)) == 0) {
    assert(strcmp(conn.host, "127.0.0.1") == 0);
    assert(conn.port == 6311);
    assert(conn.connected == true);
    assert(conn.auth_req == true);
    assert(conn.plaintext == true);
    assert(conn.rsrv_ver == 103);
    assert(conn.capabilities);
  } else {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to estabilish connection\n");
    return 1;
  }

  rexp_print(conn.capabilities);

  if ((ret = rserve_callocap(&conn, conn.capabilities, &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to return call to OCAP\n");
    return 1;
  }
  printf("OCAP return:\n");
  rexp_print(&rx);
  rexp_clear(&rx);

  rserve_disconnect(&conn);

  return 0;
}
