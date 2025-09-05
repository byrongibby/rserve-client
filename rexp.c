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

extern int set_hdr(int32_t type, int32_t len, char* y, size_t o);
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
    case XT_ARRAY_DOUBLE:
      cvector_free((double *)rx->data);
      break;
    case XT_ARRAY_INT:
      cvector_free((int *)rx->data);
      break;
    case XT_ARRAY_BOOL:
      cvector_free((char *)rx->data);
      break;
    case XT_RAW:
      cvector_free((char *)rx->data);
      break;
    case XT_ARRAY_STR:
      cvector_free((char **)rx->data);
      break;
    case XT_STR: case XT_SYMNAME:
      free((char *)rx->data);
      break;
    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      rlist_free((RList *)rx->data);
      break;
    case XT_VECTOR: case XT_VECTOR_EXP:
      rlist_free((RList *)rx->data);
      break;
    case XT_UNKNOWN:
      break;
    case XT_NULL:
      break;
  }

  *rx = (REXP) { XT_NULL, NULL, NULL};
}

bool rexp_is_vector(REXP *rx)
{
  assert(rx);

  return rx->type == XT_ARRAY_DOUBLE ||
    rx->type == XT_ARRAY_INT ||
    rx->type == XT_ARRAY_BOOL ||
    rx->type == XT_ARRAY_STR ||
    rx->type == XT_RAW;
}

bool rexp_is_list(REXP *rx)
{
  assert(rx);

  return rx->type == XT_LANG_TAG ||
    rx->type == XT_LANG_NOTAG ||
    rx->type == XT_LIST_TAG ||
    rx->type == XT_LIST_NOTAG ||
    rx->type == XT_VECTOR ||
    rx->type == XT_VECTOR_EXP;
}

bool rexp_is_string(REXP *rx)
{
  assert(rx);

   return rx->type == XT_SYMNAME ||
    rx->type == XT_STR;
}


int rexp_decode(REXP *rx, char *buf, int rxo)
{
  assert(rx);
  assert(buf);

  int rxl, eox, i;
  size_t size;
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
    rxo = rexp_decode(rx->attr, buf, rxo);
  }

  switch(rx->type) {
    case XT_NULL:
      break;

    case XT_ARRAY_DOUBLE:
      size = (eox  - rxo) / 8;
      cvector(double) doubles = NULL;
      cvector_reserve(doubles, size);
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

    case XT_ARRAY_INT:
      size = (eox  - rxo) / 4;
      cvector(int) integers = NULL;
      cvector_reserve(integers, size);
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

    case XT_ARRAY_BOOL:
      size = get_int(buf, rxo);
      rxo += 4;
      cvector(char) logicals = NULL;
      cvector_reserve(logicals, size);
      char b;
      for (size_t i = rxo; i < rxo + size; ++i) {
        b = (buf[i] == TRUE || buf[i] == FALSE) ? buf[i] : NA;
        cvector_push_back(logicals, b);
      }
      rx->data = logicals;
      rxo = eox;
      break;

    case XT_RAW:
      size = get_int(buf, rxo);
      rxo += 4;
      cvector(char) bytes = NULL;
      cvector_reserve(bytes, size);
      for (size_t i = rxo; i < rxo + size; ++i) {
        cvector_push_back(bytes, buf[i]);
      }
      rx->data = bytes;
      rxo = eox;
      break;

    case XT_ARRAY_STR:
      size = 10;
      cvector(char *) strings = NULL;
      cvector_init(strings, size, free_string);
      char *s;
      i = rxo;
      while (rxo < eox) {
        if (buf[rxo] == 0) {
          if (buf[i] == -1) {
            if (buf[i + 1] == 0) {
              s = NULL;
              cvector_push_back(strings, s);
            } else {
              /* Skip over the -1 at buf[i] */
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

  case XT_STR: case XT_SYMNAME:
    for(i = rxo; buf[i] != 0 && i < eox; i++);
    size = i - rxo;
    rx->data = calloc(size + 1, sizeof(char));
    memcpy(rx->data, buf + rxo, size);
    rxo = eox;
    break;

  case XT_LANG_TAG: case XT_LANG_NOTAG:
  case XT_LIST_TAG: case XT_LIST_NOTAG:
    REXP key, val;
    char *tag = NULL;
    size = 10;
    bool has_names = rx->type == XT_LIST_TAG || rx->type == XT_LANG_TAG;
    rx->data = malloc(sizeof(RList));
    if (rlist_init(rx->data, size, has_names) != 0) {
      fprintf(stderr, "ERROR: parsing list, failed to initialise RList\n");
      return -1;
    }
    while (rxo < eox) {
      val = (REXP) { XT_NULL, NULL, NULL };
      rxo = rexp_decode(&val, buf, rxo);
      if (rlist_has_names(rx->data)) {
        key = (REXP) { XT_NULL, NULL, NULL }, 
        rxo = rexp_decode(&key, buf, rxo);
        if (rexp_is_string(&key)) {
          tag = rexp_to_string(&key, "");
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

  case XT_VECTOR: case XT_VECTOR_EXP:
    REXP value, *names = NULL;
    char *name = NULL;
    int len;
    size = 10;
    rx->data = malloc(sizeof(RList));
    if (rlist_init(rx->data, size, false) != 0) {
      fprintf(stderr, "ERROR: parsing vector, failed to initialise RList\n");
      return -1;
    }
    while (rxo < eox) {
      value = (REXP) { XT_NULL, NULL, NULL };
      rxo = rexp_decode(&value, buf, rxo);
      rlist_add(rx->data, value);
    }
    if (rx->attr != NULL &&
        rexp_is_list(rx->attr) == true &&
        (names = rlist_get((RList *)rx->attr->data, "names")) != NULL) {
      if (names->type == XT_ARRAY_STR) {
        for (size_t i = 0; i < rlist_size(rx->data); ++i) {
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

  case XT_UNKNOWN:
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

    case XT_ARRAY_DOUBLE:
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

    case XT_ARRAY_INT:
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

    case XT_ARRAY_BOOL:
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
    case XT_ARRAY_STR:
      char *s;
      string = calloc(capacity, sizeof(char));
      if (string) {
        cvector(char *) strings = rx->data;
        s = strings[0] ? (strings[0][0] ? strings[0] : "EMPTY") : "NA";
        snprintf(string, len, "%s", s);
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
          s = strings[i] ? (strings[i][0] ? strings[i] : "EMPTY") : "NA";
          snprintf(string + strlen(string), len, "%s", s);
          size = strlen(string);
        }
      }
      break;

   case XT_STR: case XT_SYMNAME:
      size = strlen((char *)rx->data);
      string = calloc(size + 1, sizeof(char));
      if (string) {
        memcpy(string, rx->data, size);
      }
      break;

    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_LIST_TAG: case XT_LIST_NOTAG:
      //FIXME: Implement!
      break;

    case XT_VECTOR: case XT_VECTOR_EXP:
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

    case XT_UNKNOWN:
      string = calloc(capacity, sizeof(char));
      if (string) {
        snprintf(string, len, "%s", "UNKNOWN");
        size = strlen(string);
      }
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

bool rexp_equals(REXP *rx, REXP *ry)
{
  assert(rx);
  assert(ry);

  if (rx->type != ry->type) return false;

  switch(rx->type) {
    case XT_NULL:
    case XT_STR:
    case XT_VECTOR:
    case XT_SYMNAME:
    case XT_LIST_NOTAG:
    case XT_LIST_TAG:
    case XT_LANG_NOTAG:
    case XT_LANG_TAG:
    case XT_VECTOR_EXP:
    case XT_ARRAY_DOUBLE:
    case XT_ARRAY_STR:
    case XT_ARRAY_BOOL:
    case XT_RAW:
    case XT_UNKNOWN:
      break;
    case XT_ARRAY_INT:
      int *xi = (int *)rx->data, *yi = (int *)ry->data;
      if (cvector_size(xi) != cvector_size(yi)) return false;
      for (size_t i = 0; i < cvector_size(xi); ++i) {
        if (xi[i] != yi[i]) return false;
      }
      break;
    default:
      return false;
  }

  return true;
}

int rexp_binlen(REXP *rx)
{
  assert(rx);

  int len = 0;
  if (rx->attr) len += rexp_binlen(rx->attr);
  switch(rx->type) {
    case XT_NULL:
      break;

    case XT_ARRAY_INT:
      len = cvector_size((int *)rx->data) * 4;
      break;

    case XT_ARRAY_DOUBLE:
      len = cvector_size((double *)rx->data) * 8;
      break;

    case XT_ARRAY_BOOL:
      len = cvector_size((char *)rx->data) + 4;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_RAW:
      len = cvector_size((char *)rx->data) + 4;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_ARRAY_STR:
      for (size_t i = 0; i < cvector_size((char **)rx->data); ++i) {
        if(strlen(((char **)rx->data)[i]) > 0) {
          if (((char **)rx->data)[i][0] == -1) len++;
          len += strlen(((char **)rx->data)[i]); //FIXME: Need to  + 1 ??
        }
      }
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_STR: case XT_SYMNAME:
      len = rx->data ? strlen((char *)rx->data) + 1 : 1;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_LIST_TAG: case XT_LIST_NOTAG:
    case XT_VECTOR: case XT_VECTOR_EXP:
      for (size_t i = 0; i < rlist_size(rx->data); ++i) {
        REXP *x = rlist_at(rx->data, i);
        len += (x == NULL) ? 4 : rexp_binlen(x);
        if (rx->type ==  XT_LANG_TAG || rx->type ==  XT_LANG_TAG) {
          char *s = rlist_name_at(rx->data, i);
          len += 4; // header for a symbol
          len += (s == NULL) ? 1 : strlen(s) + 1;
          if ((len & 3) > 0) len = len - (len & 3) + 4;
        }
      }
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_UNKNOWN:
      break;
  }

  return (len > 0xfffff0) ? len + 8 : len + 4; // add the header
}

int rexp_encode(REXP *rx, char *buf, int rxo) 
{
  assert(rx);

  int len = rexp_binlen(rx), rxs = rxo, rxi;
  bool has_attr = false, is_large = len > 0xfffff0;

  set_hdr(rx->type | (has_attr ? XT_HAS_ATTR : 0), len - (is_large ? 8 : 4), buf, rxo);

  rxo += is_large ? 8 : 4;

  switch(rx->type) {
    case XT_NULL:
      break;

    case XT_ARRAY_INT:
      for (size_t i = 0; i < cvector_size(rx->data); ++i) {
        set_int(((int *)rx->data)[i], buf, rxo + i * 4);
      }
      break;

    case XT_ARRAY_DOUBLE:
      long l;
      for (size_t i = 0; i < cvector_size(rx->data); ++i) {
        memcpy(&l, (double *)rx->data + i, sizeof(double));
        set_long(l, buf, rxo + i * 8);
      }
      break;

    case XT_ARRAY_BOOL:
      char b;
      rxi = rxo;
      set_int(cvector_size(rx->data), buf, rxi);
      rxi += 4;
      for (size_t i = 0; i < cvector_size(rx->data); ++i) {
        b = ((char *)rx->data)[i];
        buf[rxi++] = b == NA ? 2 : (b == FALSE ? 0 : 1);
      }
      while ((rxi & 3) != 0) buf[rxi++] = 3;
      break;

    case XT_RAW:
      rxi = rxo;
      set_int(cvector_size(rx->data), buf, rxi);
      rxi += 4;
      memcpy(buf + rxi, rx->data, cvector_size(rx->data));
      break;

    case XT_ARRAY_STR:
      char **strings = (char **)rx->data;
      rxi = rxo;
      for (size_t i = 0; i < cvector_size(strings); ++i) {
        if (strings[i] != NULL) {
          memcpy(buf + rxi, strings[i], strlen(strings[i]));
          rxi += strlen(strings[i]);
        } else {
          buf[rxi++] = -1;
        }
        buf[rxi++] = 0;
      }
      while (((rxi - rxo) & 3) != 0) buf[rxi++] = 1;
      break;

   case XT_STR: case XT_SYMNAME:
      break;

    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_LIST_TAG: case XT_LIST_NOTAG:
    case XT_VECTOR: case XT_VECTOR_EXP:
      break;

    case XT_UNKNOWN:
      break;
  }

  return rxs + len;
}
