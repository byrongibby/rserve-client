#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "cvector.h"
#include "rlist.h"
#include "strings.h"

/* Custom destructor for cvector of string */
static void free_string(void *str)
{
  if (str) {
    free(*(char **)str);
  }
}

static void free_rexp(void *rx)
{
  if (rx) {
    rexp_clear(rx);
  }
}

int rlist_init(RList* rl, size_t capacity, bool has_names)
{
  assert(rl);

  rl->names = NULL;
  rl->values = NULL;

  if (has_names) {
    cvector_init(rl->names, capacity, free_string);
    if (cvector_capacity(rl->names) != capacity) return RLIST_ERROR;
  } 

  cvector_init(rl->values, capacity, free_rexp);

  return cvector_capacity(rl->values) == capacity ? RLIST_SUCCESS : RLIST_ERROR;
}

void rlist_free(RList* rl) {
  assert(rl);

  if (rl->names) cvector_free(rl->names);
  if (rl->values) cvector_free(rl->values);

  free(rl);
}

bool rlist_has_names(RList* rl)
{
  assert(rl);

  return rl->names != NULL;
}

size_t rlist_size(RList* rl)
{
  assert(rl);

  return cvector_size(rl->values);
}

static int index_of_name_(RList* rl, char* name)
{
  assert(rl);
  assert(name);

  char **it;

  if (rl->names) {
    for (it = cvector_begin(rl->names); it != cvector_end(rl->names); ++it) {
      if (strcmp(*it, name) == 0) {
        return (it - rl->names) / sizeof(char **);
      }
    }
  }

  return RLIST_ERROR;
}

int rlist_add(RList* rl, REXP value)
{
  assert(rl);

  size_t size;

  if (rl->names) {
    size = cvector_size(rl->names);
    cvector_push_back(rl->names, NULL);
    if (cvector_size(rl->names) != size + 1) return RLIST_ERROR;
  }

  size = cvector_size(rl->values);
  cvector_push_back(rl->values, value);
  return cvector_size(rl->values) == size + 1 ? RLIST_SUCCESS : RLIST_ERROR;
}

int rlist_put(RList* rl, char *name, REXP value)
{
  assert(rl);

  int ret;

  // Name is NULL
  if (name == NULL) {
    return rlist_add(rl, value);
  }

  // Name already exists in list
  if (rl->names) {
    int i = index_of_name_(rl, name);
    if (i >= 0) {
      rl->values[i] = value;
      return RLIST_SUCCESS;
    }
  }

  // Name added to the end of the list
  if ((ret = rlist_add(rl, value)) != 0) return ret;
  if (!rl->names)
    cvector_init(rl->names, cvector_capacity(rl->values), free_string);
  rl->names[cvector_size(rl->names) - 1] = name;

  return ret;
}

int rlist_assign_name(RList *rl, size_t index, char *name)
{
  assert(rl);

  if (!rl->names) {
    cvector_init(rl->names, cvector_capacity(rl->values), free_string);
    cvector_resize(rl->names, cvector_size(rl->values), NULL);
  }

  cvector_insert(rl->names, index, name);

  return rl->names[index] == name ? RLIST_SUCCESS : RLIST_ERROR;
}

REXP *rlist_get(RList* rl, char* name)
{
  assert(rl);

  if (rl->names) {
    int i = index_of_name_(rl, name);
    if (i >= 0) return cvector_at(rl->values, i);
  }

  return NULL;
}

REXP *rlist_at(RList* rl, size_t index)
{
  assert(rl);

  return cvector_at(rl->values, index);
}

char *rlist_name_at(RList* rl, size_t index)
{
  assert(rl);

  if (rl->names) return rl->names[index];

  return NULL;
}
