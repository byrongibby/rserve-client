#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "cvector.h"
#include "rexp.h"
#include "rlist.h"
#include "rserve.h"

extern int get_len(char* y, size_t o);
extern void set_int(int32_t x, char* y, size_t o);
extern int get_int(char* y, size_t o);
extern void set_long(int64_t x, char* y, size_t o);
extern long get_long(char* y, size_t o);


/* Custom destructor for vector of string */
static void free_string(void *str) {
  if (str) {
    free(*(char **)str);
  }
}

void rexp_free(REXP *rx)
{
  if (rx) {
    rexp_clear(rx);
    free(rx);
  }
}

void rexp_clear(REXP *rx)
{
  assert(rx);

  if (rx->attr) rexp_free(rx->attr);

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      cvector_free((double *)rx->data);
      break;
    case XT_INT: case XT_ARRAY_INT:
      cvector_free((int *)rx->data);
      break;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      cvector_free((char *)rx->data);
      break;
    case XT_RAW:
      cvector_free((char *)rx->data);
      break;
    case XT_STR: case XT_ARRAY_STR:
      cvector_free((char **)rx->data);
      break;
    case XT_SYMNAME:
      free((char *)rx->data);
      break;
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      rlist_free((RList *)rx->data);
      break;
    case XT_VECTOR:
      rlist_free((RList *)rx->data);
      break;
    case XT_NULL:
      break;
  }

  *rx = (REXP) { XT_NULL, NULL, NULL};
}

bool rexp_is_symbol(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_NULL:
      return false;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return false;
    case XT_INT: case XT_ARRAY_INT:
      return false;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      return false;
    case XT_RAW:
      return false;
    case XT_STR: case XT_ARRAY_STR:
      return false;
    case XT_SYMNAME:
      return true;
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      return false;
    case XT_VECTOR:
      return false;
    default:
      return false;
  }
}

bool rexp_is_vector(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_NULL:
      return false;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return true;
    case XT_INT: case XT_ARRAY_INT:
      return true;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      return true;
    case XT_RAW:
      return true;
    case XT_STR: case XT_ARRAY_STR:
      return true;
    case XT_SYMNAME:
      return false;
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      return false;
    case XT_VECTOR:
      return false;
    default:
      return false;
  }
}

bool rexp_is_list(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_NULL:
      return false;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return false;
    case XT_INT: case XT_ARRAY_INT:
      return false;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      return false;
    case XT_RAW:
      return false;
    case XT_STR: case XT_ARRAY_STR:
      return false;
    case XT_SYMNAME:
      return false;
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      return true;
    case XT_VECTOR:
      return true;
    default:
      return false;
  }
}

bool rexp_is_string(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_NULL:
      return false;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return false;
    case XT_INT: case XT_ARRAY_INT:
      return false;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      return false;
    case XT_RAW:
      return false;
    case XT_STR: case XT_ARRAY_STR:
      return true;
    case XT_SYMNAME:
      return false;
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      return false;
    case XT_VECTOR:
      return false;
    default:
      return false;
  }
}


int rexp_parse(REXP *rx, char *buf, int rxo)
{
  assert(rx);
  assert(buf);

  int rxl, eox, size, i, len;
  bool has_attr, is_long;

  rxl = get_len(buf, rxo);
  rx->type = (int)(*(buf + rxo) & 63);
  has_attr = (*(buf + rxo) & 128) != 0;
  is_long = (*(buf + rxo) & 64) != 0;

  rxo += 4;
  if (is_long) rxo += 4;
  eox = rxl + rxo;

  if (has_attr) {
    rx->attr = malloc(sizeof(REXP));
    rx->attr->attr = NULL;
    rxo = rexp_parse(rx->attr, buf, rxo);
  }

  switch(rx->type) {
    case XT_NULL:
      break;

    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      cvector(double) doubles = NULL; //FIXME: cvector_reserve() where array size is known
      double d;
      long l;
      while (rxo < eox) {
        l = get_long(buf, rxo);
        memcpy(&d, &l, sizeof(long));
        cvector_push_back(doubles, d);
        rxo += 8;
      }
      rx->data = doubles;
      if (rxo != eox) {
        fprintf(stderr, "WARN: double SEXP size mismatch\n");
        rxo = eox;
      }
      break;

    case XT_INT: case XT_ARRAY_INT:
      cvector(int) integers = NULL;
      while (rxo < eox) {
        i = get_int(buf, rxo);
        cvector_push_back(integers, i);
        rxo += 4;
      }
      rx->data = integers;
      if (rxo != eox) {
        fprintf(stderr, "WARN: integer SEXP size mismatch\n");
        rxo = eox;
      }
      break;

    case XT_LOGICAL: case XT_ARRAY_BOOL:
      size = 1;
      if (rx->type == XT_ARRAY_BOOL) {
        size = get_int(buf, rxo);
        rxo += 4;
      }
      cvector(char) logicals = NULL;
      char b;
      for (int i = rxo; i < rxo + size; ++i) {
        b = (buf[i] == TRUE || buf[i] == FALSE) ? buf[i] : NA;
        cvector_push_back(logicals, b);
      }
      rx->data = logicals;
      if (rx->type == XT_LOGICAL) {
        rxo++;
        if (rxo != eox) {
          if (rxo + 3 != eox) {
            fprintf(stderr, "WARN: logical SEXP size mismatch\n");
          }
        }
      }     
      rxo = eox;
      break;

    case XT_RAW:
      size = get_int(buf, rxo);
      rxo += 4;
      cvector(char) bytes = NULL;
      for (int i = rxo; i < rxo + size; ++i) {
        cvector_push_back(bytes, buf[i]);
      }
      rx->data = bytes;
      rxo = eox;
      break;

    case XT_STR: case XT_ARRAY_STR:
      cvector(char *) strings = NULL;
      cvector_init(strings, 1, free_string);
      char *s;
      i = rxo;
      while (rxo < eox) {
        if (buf[rxo] == 0) {
          if (buf[i] == -1) {
            if (buf[i + 1] == 0) {
              s = calloc(1, sizeof(char));
              cvector_push_back(strings, s);
            } else {
              s = calloc(rxo - i, sizeof(char));
              memcpy(s, buf + i + 1, rxo - i - 1);
              cvector_push_back(strings, s);
            }
          } else {
            s = calloc(rxo - i + 1, sizeof(char));
            memcpy(s, buf + i, rxo - i);
            cvector_push_back(strings, s);
          }
          i = rxo + 1;
        }
        rxo++;
      }
      rx->data = strings;
      rxo = eox;
      break;

  case XT_SYMNAME:
    for(i = rxo; buf[i] != 0 && i < eox; i++);
    len = i - rxo;
    rx->data = calloc(len + 1, sizeof(char));
    memcpy(rx->data, buf + rxo, len);
    rxo = eox;
    break;

  case XT_LIST_TAG: case XT_LIST_NOTAG:
    REXP key, val;
    char *tag = NULL;
    rx->data = malloc(sizeof(RList));
    if (rlist_init(rx->data, 10, rx->type == XT_LIST_TAG) != 0) {
      fprintf(stderr, "ERROR: parsing list, failed to initialise RList\n");
      return -1;
    }
    while (rxo < eox) {
      val = (REXP) { XT_NULL, NULL, NULL };
      rxo = rexp_parse(&val, buf, rxo);
      if (rlist_has_names(rx->data)) {
        key = (REXP) { XT_NULL, NULL, NULL }, 
        rxo = rexp_parse(&key, buf, rxo);
        if (rexp_is_string(&key) || rexp_is_symbol(&key)) {
          tag = rexp_to_string(&key, ".");
        }
        rexp_clear(&key);
      }
      if (tag == NULL) {
        rlist_add(rx->data, val);
      } else {
        rlist_put(rx->data, tag, val);
      }
    }
    if (rxo != eox) {
      fprintf(stderr, "WARN: list SEXP size mismatch\n");
      rxo = eox;
    }
    break;

  case XT_VECTOR:
    REXP value, *names = NULL;
    char *name = NULL;
    rx->data = malloc(sizeof(RList));
    if (rlist_init(rx->data, 10, false) != 0) {
      fprintf(stderr, "ERROR: parsing vector, failed to initialise RList\n");
      return -1;
    }
    while (rxo < eox) {
      value = (REXP) { XT_NULL, NULL, NULL };
      rxo = rexp_parse(&value, buf, rxo);
      rlist_add(rx->data, value);
    }
    if (rx->attr != NULL &&
        rexp_is_list(rx->attr) == true &&
        (names = rlist_get((RList *)rx->attr->data, "names")) != NULL) {
      if (rexp_is_string(names) && rexp_is_vector(names)) {
        for (size_t i = 0; i < rlist_size(rx->data); i++) {
          if (i < cvector_size(names->data)) {
            len = strlen(((char **)names->data)[i]);
            name = malloc(len + 1);
            memcpy(name, ((char **)names->data)[i], len + 1);
            rlist_assign_name(rx->data, i, name);
          } else {
            rlist_assign_name(rx->data, i, "");
          }
        }
      }
    }
    if (rxo != eox) {
      fprintf(stderr, "WARN: vector SEXP size mismatch\n");
      rxo = eox;
    }
    break;
  }

  return rxo;
}

char *rexp_to_string(REXP *rx, char *sep)
{
  assert(rx);
  assert(sep);

  size_t seplen = strlen(sep), len = 100 + seplen, capacity = 10 * len, size = 0;
  char *string;

  switch(rx->type) {
    case XT_NULL:
      string = calloc(capacity, sizeof(char));
      if (string) {
        snprintf(string, len, "%s", "NULL");
        size = strlen(string);
      }
      break;

    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      string = calloc(capacity, sizeof(char));
      if (string) {
        cvector(double) doubles = rx->data;
        snprintf(string, len, "%f", doubles[0]);
        size = strlen(string);
        for (size_t i = 1; i < cvector_size(doubles); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string + capacity / 2, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          snprintf(string + strlen(string), len, "%f", doubles[i]);
          size = strlen(string);
        }
      }
      break;

    case XT_INT: case XT_ARRAY_INT:
      string = calloc(capacity, sizeof(char));
      if (string) {
        cvector(int) integers = rx->data;
        if (NA_INTERNAL == integers[0]) {
          snprintf(string, len, "%s", "NA");
        } else {
          snprintf(string, len, "%d", integers[0]);
        }
        size = strlen(string);
        for (size_t i = 1; i < cvector_size(integers); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string + capacity / 2, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          if (NA_INTERNAL == integers[i]) {
            snprintf(string + strlen(string), len, "%s", "NA");
          } else {
            snprintf(string + strlen(string), len, "%d", integers[i]);
          }
          size = strlen(string);
        }
      }
      break;

    case XT_LOGICAL: case XT_ARRAY_BOOL:
      string = calloc(capacity, sizeof(char));
      if (string) {
        cvector(char) logicals = rx->data;
        if (TRUE == logicals[0]) {
          snprintf(string, len, "%s", "TRUE");
        } else if (FALSE == logicals[0]) {
          snprintf(string, len, "%s", "FALSE");
        } else {
          snprintf(string, len, "%s", "NA");
        }
        size = strlen(string);
        for (size_t i = 1; i < cvector_size(logicals); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string + capacity / 2, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          if (TRUE == logicals[i]) {
            snprintf(string + strlen(string), len, "%s", "TRUE");
          } else if (FALSE == logicals[i]) {
            snprintf(string + strlen(string), len, "%s", "FALSE");
          } else {
            snprintf(string + strlen(string), len, "%s", "NA");
          }
          size = strlen(string);
        }
      }
      break;

    case XT_RAW:
      string = calloc(capacity, sizeof(char));
      if (string) {
        char *raw = rx->data;
        snprintf(string, len, "%x", raw[0]);
        size = strlen(string);
        for (size_t i = 1; i < cvector_size((char *)rx->data); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string + capacity / 2, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          snprintf(string + strlen(string), len, "%x", raw[i]);
          size = strlen(string);
        }
      }
      break;

    //FIXME: improve to handle arbitrarily long strings
    case XT_STR: case XT_ARRAY_STR:
      string = calloc(capacity, sizeof(char));
      if (string) {
        cvector(char *) strings = rx->data;
        snprintf(string, len, "%s", strings[0][0] ? strings[0] : "NA");
        size = strlen(string);
        for (size_t i = 1; i < cvector_size(strings); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string + capacity / 2, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          snprintf(string + strlen(string), len, "%s", strings[i][0] ? strings[i] : "NA");
          size = strlen(string);
        }
      }
      break;

    case XT_SYMNAME:
      size = strlen((char *)rx->data);
      string = calloc(size + 1, sizeof(char));
      if (string) {
        memcpy(string, rx->data, size);
      }
      break;

    case XT_LIST_TAG: case XT_LIST_NOTAG:
      //FIXME: Implement!
      break;

    case XT_VECTOR:
      char *tmp, *name, *value;
      cvector(char *) strings = NULL;

      cvector_init(strings, 10, free_string);
      size = 0;

      if (rlist_has_names(rx->data)) {
        for (size_t i = 0; i < rlist_size(rx->data); i++) {
          tmp = rlist_name_at(rx->data, i);
          if (tmp == NULL || *tmp == '\0') {
            name = calloc(100, sizeof(char));
            sprintf(name, "[[%lu]]", i + 1);
            cvector_push_back(strings, name);
          } else {
            name = calloc(strlen(tmp) + 2, sizeof(char));
            sprintf(name, "$%s", tmp);
            cvector_push_back(strings, name);
          }

          value = rexp_to_string(rlist_at(rx->data, i), " ");
          cvector_push_back(strings, value);

          size += strlen(name) + strlen(value) + 2;
        }
      } else {
        for (size_t i = 0; i < rlist_size(rx->data); i++) {
          name = calloc(100, sizeof(char));
          sprintf(name, "[[%lu]]", i + 1);
          cvector_push_back(strings, name);

          value = rexp_to_string(rlist_at(rx->data, i), " ");
          cvector_push_back(strings, value);

          size += strlen(name) + strlen(value) + 2;
        }
      }

      string = calloc(size + 1, sizeof(char));
      if (cvector_size(strings) > 0) strcat(string, strings[0]);
      for (size_t i = 1; i < cvector_size(strings); ++i) {
        strcat(string, "\n");
        strcat(string, strings[i]);
      }

      cvector_free(strings);
      break;
  }

  return realloc(string, size + 1);
}

void rexp_print(REXP *rx)
{
  char *const s = rexp_to_string(rx, " ");
  puts(s);
  free(s);
}

int rexp_binlen(REXP *rx)
{
  int len = 0;
  if (rx->attr) len += rexp_binlen(rx->attr);
  switch(rx->type) {
    case XT_NULL:
      break;
    case XT_SYMNAME:
      len += rx->data ? strlen((char *)rx->data) + 1 : 1;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;
    case XT_INT: case XT_ARRAY_INT:
      len += cvector_size((int *)rx->data) * 4;
      break;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      len += cvector_size((double *)rx->data) * 8;
      break;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      len += cvector_size((char *)rx->data) + 4;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;
    case XT_RAW:
      len += cvector_size((char *)rx->data) + 4;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;
    case XT_STR: case XT_ARRAY_STR:
      for (size_t i = 0; i < cvector_size((char **)rx->data); ++i) {
        if(strlen(((char **)rx->data)[i]) > 0) {
          if (((char **)rx->data)[i][0] == -1) len++;
          len += strlen(((char **)rx->data)[i]); //FIXME: Need to  + 1 ??
        }
      }
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;
    case XT_LIST_NOTAG: case XT_LIST_TAG: case XT_VECTOR:
      break;
  }
  return len;
}

int rexp_to_binary(REXP *rx, char *buf, int rxo) 
{
  buf++;
  switch(rx->type) {
    case XT_NULL:
      break;
    case XT_SYMNAME:
      break;
    case XT_INT: case XT_ARRAY_INT:
      break;
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      break;
    case XT_STR: case XT_ARRAY_STR:
      break;
    case XT_LOGICAL: case XT_ARRAY_BOOL:
      break;
    case XT_RAW:
      break;
    case XT_LIST_NOTAG: case XT_LIST_TAG: case XT_VECTOR:
      break;
  }
  return rxo;
}
