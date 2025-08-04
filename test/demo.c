#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rexp.h"
#include "rserve.h"

int main(void)
{
  int err;
  RConnection conn;
  REXP rx = { XT_NULL, NULL, NULL };

  if ((err = rserve_connect(&conn, "127.0.0.1", 6311)) == 0) {
    assert(strcmp(conn.host, "127.0.0.1") == 0);
    assert(conn.port == 6311);
    assert(conn.connected == true);
    assert(conn.auth_req == true);
    assert(conn.plaintext == true);
    assert(conn.rsrv_ver == 103);
  } else {
    printf("Rserve error: %s\n", rserve_error(err));
    printf("Failed to estabilish connection\n");
    return 1;
  }

  if ((err = rserve_login(&conn, "Byron", "password")) != 0) {
    printf("Rserve error: %s\n", rserve_error(err));
    printf("Failed to log in\n");
    return 1;
  }

  if ((err = rserve_eval(&conn, "NULL", &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(err));
    printf("Failed to evaluate NULL return\n");
    return 1;
  }
  printf("NULL return:\n");
  rexp_print(&rx);
  rexp_clear(&rx);
  
  if ((err = rserve_eval(&conn, "c(NA, rnorm(5))", &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(err));
    printf("Failed to evaluate vector of doubles\n");
    return 1;
  }
  printf("Vector of doubles:\n");
  rexp_print(&rx);
  rexp_clear(&rx);


  if ((err = rserve_eval(&conn, "as.integer(c(1:5, NA, 7))", &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(err));
    printf("Failed to evaluate vector of int\n");
    return 1;
  }
  printf("Vector of int:\n");
  rexp_print(&rx);
  rexp_clear(&rx);

  /*
  if (rserve_eval(&conn, "c(TRUE, FALSE, NA, TRUE, TRUE)", &rx) == 0) {
    printf("Vector of logical:\n");
    rexp_print(&rx);
    printf("\n");
  }
  rexp_clear(&rx);

  if (rserve_eval(&conn, "charToRaw('a b c')", &rx) == 0) {
      printf("Vector of raw:\n");
      rexp_print(&rx);
      printf("\n");
  }
  rexp_clear(&rx);

  if (rserve_eval(&conn, "c('abra', NA, 'ca', 'dabra')", &rx) == 0) {
    printf("Vector of strings (character vector):\n");
    rexp_print(&rx);
    printf("\n");
  }
  rexp_clear(&rx);

  //"list(foo = list(1, 'Z', FALSE), 'bar' = PI, 'baz')"
  if(rserve_eval(&conn, "list(a = 1, b = 2, c = 3)", &rx) == 0) {
    printf("Generic vector (named list):\n");
    rexp_print(&rx);
    printf("\n");
  }
  rexp_clear(&rx);
  */

  rserve_disconnect(&conn);

  return 0;
}
