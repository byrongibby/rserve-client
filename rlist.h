#ifndef R_LIST_H_ 
#define R_LIST_H_

#include <stdbool.h>

#include "rexp.h"

#define RLIST_SUCCESS 0
#define RLIST_ERROR -1

typedef struct RList
{
  char **names;
  REXP *values;
} RList;

int rlist_init(RList *rl, size_t capacity, bool has_names);
void rlist_free(RList *rl);
bool rlist_has_names(const RList *rl);
size_t rlist_size(const RList *rl);
int rlist_add(RList *rl, REXP element);
int rlist_put(RList *rl, char *name, REXP value);
int rlist_assign_name(RList *rl, size_t index, char *name);
REXP *rlist_get(const RList *rl, char *name);
REXP *rlist_at(const RList *rl, size_t index);
char *rlist_name_at(const RList *rl, size_t index);

#endif /* R_LIST_H_ */
