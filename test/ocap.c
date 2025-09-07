#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvector.h"
#include "rexp.h"
#include "rlist.h"
#include "rserve.h"

void free_string(void *str) {
  if (str) {
    free(*(char **)str);
  }
}

int main(void)
{
  int ret;
  RConnection conn = { 0 };
  REXP rx = { 0 }, ocap = { 0 }, name = { 0 }, pass = { 0 };
  RList rl;
  cvector(char *) n = NULL;
  cvector(char *) p = NULL;

  cvector_init(n, 1, free_string);
  cvector_init(p, 1, free_string);

  cvector_push_back(n, "mike");
  cvector_push_back(p, "mypwd");

  name.type = XT_ARRAY_STR;
  name.data = n;
  pass.type = XT_ARRAY_STR;
  pass.data = p;

  if ((ret = rserve_connect(&conn, "127.0.0.1", 6311)) == 0) {
    assert(strcmp(conn.host, "127.0.0.1") == 0);
    assert(conn.port == 6311);
    assert(conn.connected == true);
    assert(conn.rsrv_ver == 103);
    assert(conn.capabilities);
  } else {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to estabilish connection\n");
    return 1;
  }
 
  rlist_init(&rl, 3, false);

  rlist_add(&rl, *conn.capabilities);
  rlist_add(&rl, name);
  rlist_add(&rl, pass);

  ocap.type = XT_LANG_NOTAG;
  ocap.data = &rl;

  if ((ret = rserve_callocap(&conn, &ocap, &rx)) != 0) {
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
