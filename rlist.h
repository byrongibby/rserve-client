#ifndef R_LIST_H_ 
#define R_LIST_H_

#include <stdbool.h>

#include "rexp.h"
#include "vector/vector.h"

typedef struct RList
{
  char *names;
  void *values;
} RList;

int rlist_init(RList *rl, size_t capacity, bool has_names);
void rlist_free(RList *rl);
bool rlist_has_names(RList *rl);
size_t rlist_size(RList *rl);
int rlist_add(RList *rl, REXP *element);
int rlist_put(RList *rl, char *name, REXP *value);
int rlist_assign_name(RList *rl, size_t index, char *name);
REXP *rlist_get(RList *rl, char *name);
REXP *rlist_at(RList* rl, size_t index);
char *rlist_name_at(RList* rl, size_t index);

#endif /* R_LIST_H_ */
