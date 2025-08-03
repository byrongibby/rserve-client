#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "rexp_vector.h"
#include "rlist.h"
#include "strings.h"

int rlist_setup(RList* rl, size_t capacity, bool has_names)
{
  Vector v = { NULL, NULL };

  rl->names = v;
  rl->values = v;

  if (has_names && (strings_vector_setup(&rl->names, capacity) != 0)) {
    return VECTOR_ERROR;
  } 

  return rexp_vector_setup(&rl->values, capacity);
}

void rlist_destroy(RList* rl) {
  if (vector_is_initialized(&rl->names)) vector_destroy(&rl->names);
  if (vector_is_initialized(&rl->values)) vector_destroy(&rl->values);
}

bool rlist_has_names(RList* rl)
{
  return vector_is_initialized(&rl->names);
}

size_t rlist_size(RList* rl)
{
  return vector_size(&rl->values);
}

int index_of_name_(RList* rl, char* name)
{
  Iterator iterator, last;

  if(rl == NULL) return VECTOR_ERROR;

  if (vector_is_initialized(&rl->names)) {
    iterator = vector_begin(&rl->names); 
    last = vector_end(&rl->names); 
    for (; !iterator_equals(&iterator, &last); iterator_increment(&iterator)) {
      if (strcmp(*(char **)iterator_get(&iterator), name) == 0) {
        return iterator_index(&rl->names, &iterator);
      }
    }
  }

  return VECTOR_ERROR;
}

int rlist_add(RList* rl, REXP *value)
{
  char *name = NULL;

  if(rl == NULL) return VECTOR_ERROR;

  if (vector_is_initialized(&rl->names) &&
      (vector_push_back(&rl->names, &name) != 0)) {
    return VECTOR_ERROR;
  }

  return vector_push_back(&rl->values, value);
}

int rlist_put(RList* rl, char* name, REXP *value)
{
  char *empty_name = NULL;

  if(rl == NULL) return VECTOR_ERROR;

  if (name == NULL) {
    return rlist_add(rl, value);
  }

  if (vector_is_initialized(&rl->names)) {
    int i = index_of_name_(rl, name);
    if (i >= 0) {
      return vector_assign(&rl->values, i, value);
    }
  }

  rlist_add(rl, value);

  if (!vector_is_initialized(&rl->names)) {
    strings_vector_setup(&rl->names, vector_capacity(&rl->values));
    while (vector_size(&rl->names) < vector_size(&rl->values)) {
      vector_push_back(&rl->names, &empty_name);
    }
  }

  return vector_assign(&rl->names, vector_size(&rl->names) - 1, &name);
}

int rlist_assign_name(RList *rl, size_t index, char *name)
{
  if(rl == NULL) return VECTOR_ERROR;

  if (!vector_is_initialized(&rl->names)) {
    strings_vector_setup(&rl->names, vector_capacity(&rl->values));
    vector_resize(&rl->names, vector_size(&rl->values));
  }
  return vector_insert(&rl->names, index, &name);
}

REXP *rlist_get(RList* rl, char* name)
{
  if(rl == NULL) return NULL;

  if (vector_is_initialized(&rl->names)) {
    int i = index_of_name_(rl, name);
    if (i >= 0) return vector_get(&rl->values, i);
  }
  return NULL;
}

REXP *rlist_at(RList* rl, size_t index)
{
  if(rl == NULL) return NULL;

  return vector_get(&rl->values, index);
}

char *rlist_name_at(RList* rl, size_t index)
{
  if(rl == NULL) return NULL;

  if (vector_is_initialized(&rl->names)) {
    return *(char **)vector_get(&rl->names, index);
  } else {
    return NULL;
  }
