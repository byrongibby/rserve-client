#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvector.h"
#include "rexp.h"
#include "rlist.h"
#include "rserve.h"
#include "utilities.h"

/* Custom destructor for cvector of string
 */
void free_string(void *str) {
  if (str) {
    free(*(char **)str);
  }
}

int main(void)
{
  int ret;
  char *u = malloc(5), *p = malloc(6);
  RConnection conn = { 0 };
  REXP rx = { 0 }, ocap = { 0 }, args[2] = { 0 };

  if ((ret = rserve_connect(&conn, "127.0.0.1", 6311)) == 0) {
    assert(strcmp(conn.host, "127.0.0.1") == 0);
    assert(conn.port == 6311);
    assert(conn.connected == true);
    assert(conn.rsrv_ver == 103);
    assert(conn.capabilities.type != XT_NULL);
  } else {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to estabilish connection\n");
    return 1;
  }

  printf("Server OCAPs:\n");
  rexp_print(&conn.capabilities);
  rexp_print(conn.capabilities.attr);

  /* First argument (user) to auth function (capability)
   */
  memcpy(u, "mike", 5);
  cvector(char *) user = NULL;
  cvector_init(user, 1, free_string);
  cvector_push_back(user, u);

  args[0].type = XT_ARRAY_STR;
  args[0].data = user;
  args[0].attr = NULL;

  /* Second argument (pass) to auth function (capability)
   */
  memcpy(p, "mypwd", 6);
  cvector(char *) pass = NULL;
  cvector_init(pass, 1, free_string);
  cvector_push_back(pass, p);

  args[1].type = XT_ARRAY_STR;
  args[1].data = pass;
  args[1].attr = NULL;

  /* Create ocap request from capability and arg REXPs
   */
  ocap = create_call(&conn.capabilities, args, 2);

  if ((ret = rserve_callocap(&conn, &ocap, &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to return call to OCAP\n");
    return 1;
  }
  printf("OCAP auth('mike', 'mypwd') call return:\n");
  rexp_print(&rx);

  rexp_clear(&ocap);

  char *s = malloc(17);
  REXP ocap2 = { 0 }, args2[1] = { 0 };

  memcpy(s, "R.version.string", 17);
  cvector(char *) src = NULL;
  cvector_init(src, 1, free_string);
  cvector_push_back(src, s);

  args2[0].type = XT_ARRAY_STR;
  args2[0].data = src;
  args2[0].attr = NULL;

  ocap2 = create_call(rlist_get((RList *)rx.data, "parse_eval"), args2, 1);

  rexp_clear(&rx);

  if ((ret = rserve_callocap(&conn, &ocap2, &rx)) != 0) {
    printf("Rserve error: %s\n", rserve_error(ret));
    printf("Failed to return call to OCAP\n");
    return 1;
  }
  printf("OCAP parse_eval('R.version.string') call return:\n");
  rexp_print(&rx);
  rexp_clear(&rx);

  rexp_clear(&ocap2);

  rserve_disconnect(&conn);

  return 0;
}
