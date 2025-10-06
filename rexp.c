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

extern int set_hdr(int32_t type, int32_t len, char *y, size_t o);
extern int get_len(const char *y, size_t o);
extern void set_int(int32_t x, char *y, size_t o);
extern int get_int(const char *y, size_t o);
extern void set_long(int64_t x, char *y, size_t o);
extern long get_long(const char *y, size_t o);


/* Custom destructor for cvector of string */
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

  if (rx->data) {
    switch (rx->type) {
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
  }

  *rx = (REXP) { XT_NULL, NULL, NULL };
}

REXP *rexp_copy(REXP *ry, const REXP *rx)
{
  assert(rx);
  assert(ry);

  int len;

  if (rx->attr) {
    if ((ry->attr = malloc(sizeof(REXP))) == NULL) return NULL;
    if (rexp_copy(ry->attr, rx->attr) == NULL) {
      free(ry->attr);
      return NULL;
    }
  } else {
    ry->attr = NULL;
  }

  switch (rx->type) {
    case XT_NULL:
      break;

    case XT_ARRAY_INT:
      int *x_ints = rx->data, *y_ints = NULL;
      cvector_copy(x_ints, y_ints);
      if (y_ints == NULL) return NULL;
      ry->data = y_ints;
      break;

    case XT_ARRAY_DOUBLE:
      double *x_doubles = rx->data, *y_doubles = NULL;
      cvector_copy(x_doubles, y_doubles);
      if (y_doubles == NULL) return NULL;
      ry->data = y_doubles;
      break;

    case XT_ARRAY_BOOL: case XT_RAW:
      char *x_bytes = rx->data, *y_bytes = NULL;
      cvector_copy(x_bytes, y_bytes);
      if (y_bytes == NULL) return NULL;
      ry->data = y_bytes;
      break;

    case XT_ARRAY_STR:
      // Manually copy strings after initialising cvector and
      // setting it to the correct size
      char **x_strings = rx->data, **y_strings = NULL; 
      cvector_init(y_strings, cvector_capacity(x_strings), free_string);
      if (y_strings == NULL) return NULL;
      cvector_resize(y_strings, cvector_size(x_strings), NULL);
      for (size_t i = 0; i < cvector_size(y_strings); ++i) {
        len = strlen(x_strings[i]);
        if ((y_strings[i] = calloc(len + 1, sizeof(char)))) {
          memcpy(y_strings[i], x_strings[i], len);
        } else {
          fprintf(stderr, "WARN: while copying array of strings rexp, ");
          fprintf(stderr, "failed to alloc memory, strings[%lu] not set\n", i);
        }
      }
      ry->data = y_strings;
      break;

    case XT_STR: case XT_SYMNAME:
      char *x_string = rx->data, *y_string = ry->data; 
      len = strlen(x_string);
      if((y_string = calloc(len + 1, sizeof(char))) == NULL) return NULL;
      memcpy(y_string, x_string, len);
      if (y_string == NULL) return NULL;
      break;

    case XT_LIST_NOTAG: case XT_LIST_TAG:
    case XT_LANG_NOTAG: case XT_LANG_TAG:
    case XT_VECTOR: case XT_VECTOR_EXP:
      // Manually copy names and values after setting cvector to the correct
      // size - rlist_init() takes care of the initialisation
      char **y_names, **x_names;
      REXP *y_values, *x_values, null_value = { 0 };
      len = rlist_size(rx->data);
      if ((ry->data = malloc(sizeof(RList))) == NULL) return NULL;
      if (!rlist_has_names(rx->data)) {
        if (rlist_init(ry->data, len, false) != 0) return NULL;
      } else {
        if (rlist_init(ry->data, len, true) != 0) return NULL;
        y_names = ((RList *)ry->data)->names;
        x_names = ((RList *)rx->data)->names;
        cvector_resize(y_names, cvector_size(x_names), NULL);
        for (size_t i = 0; i < cvector_size(y_names); ++i) {
          len = strlen(x_names[i]);
          if ((y_names[i] = calloc(len + 1, sizeof(char)))) {
            memcpy(y_names[i], x_names[i], len);
          } else {
            fprintf(stderr, "WARN: while copying names in list/vector rexp, ");
            fprintf(stderr, "failed to alloc memory, names[%lu] not set\n", i);
          }
        }
      }
      y_values = ((RList *)ry->data)->values;
      x_values = ((RList *)rx->data)->values;
      cvector_resize(y_values, cvector_size(x_values), null_value);
      for (size_t i = 0; i < cvector_size(y_values); ++i) {
        rexp_copy(y_values + i, x_values + i);
      }
      break;

    case XT_UNKNOWN:
      return NULL;

    default:
      return NULL;
  }

  ry->type = rx->type;

  return ry;
}


bool rexp_is_vector(const REXP *rx)
{
  assert(rx);

  return rx->type == XT_ARRAY_DOUBLE ||
    rx->type == XT_ARRAY_INT ||
    rx->type == XT_ARRAY_BOOL ||
    rx->type == XT_ARRAY_STR ||
    rx->type == XT_RAW;
}

bool rexp_is_list(const REXP *rx)
{
  assert(rx);

  return rx->type == XT_LANG_TAG ||
    rx->type == XT_LANG_NOTAG ||
    rx->type == XT_LIST_TAG ||
    rx->type == XT_LIST_NOTAG ||
    rx->type == XT_VECTOR ||
    rx->type == XT_VECTOR_EXP;
}

bool rexp_is_string(const REXP *rx)
{
  assert(rx);

   return rx->type == XT_SYMNAME ||
    rx->type == XT_STR;
}


int rexp_decode(REXP *rx, const char *buf, int rxo)
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

  switch (rx->type) {
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
        b = (buf[i] == LGL_TRUE || buf[i] == LGL_FALSE) ? buf[i] : LGL_NA;
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
    fprintf(stderr, "WARN: while decoding REXP, unknown type.\n");
    rxo = eox;
    break;

  default:
    fprintf(stderr, "WARN: while decoding REXP, unimplemented type.\n");
    rxo = eox;
    break;
  }

  return rxo;
}

char *rexp_to_string(const REXP *rx, const char *sep)
{
  assert(rx);
  assert(sep);

  size_t seplen = strlen(sep), len = 100 + seplen, capacity = 10 * len, size = 0;
  char *string = NULL;
  cvector(char *) strings = NULL;

  switch (rx->type) {
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
        if (LGL_TRUE == logicals[0]) {
          snprintf(string, len, "%s", "TRUE");
        } else if (LGL_FALSE == logicals[0]) {
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
          if (LGL_TRUE == logicals[i]) {
            snprintf(string + strlen(string), len, "%s", "TRUE");
          } else if (LGL_FALSE == logicals[i]) {
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

    case XT_ARRAY_STR:
      strings = rx->data;
      size = 0;
      if (cvector_size(strings) > 0) {
        size += (strings[0] && strings[0][0]) ? strlen(strings[0]) : 0;
        size += 2;
      }
      for (size_t i = 1; i < cvector_size(strings); ++i) {
        size += strlen(sep);
        size += (strings[0] && strings[0][0]) ? strlen(strings[0]) : 0;
        size += 2;
      }
      string = calloc(size + 1, sizeof(char));
      if (cvector_size(strings) > 0) {
        if (strings[0]) {
          if (strings[0][0]) {
            strcat(string, "\"");
            strcat(string, strings[0]);
            strcat(string, "\"");
          } else {
            strcat(string, "\"\"");
          }
        } else {
          strcat(string, "NA");
        }
      }
      for (size_t i = 1; i < cvector_size(strings); ++i) {
        strcat(string, sep);
        if (strings[i]) {
          if (strings[i][0]) {
            strcat(string, "\"");
            strcat(string, strings[i]);
            strcat(string, "\"");
          } else {
            strcat(string, "\"\"");
          }
        } else {
          strcat(string, "NA");
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
    case XT_VECTOR: case XT_VECTOR_EXP:
      char *tmp, *name, *value;

      cvector_init(strings, 10, free_string);
      size = 0;

      if (rlist_has_names(rx->data)) {
        for (size_t i = 0; i < rlist_size(rx->data); ++i) {
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
        for (size_t i = 0; i < rlist_size(rx->data); ++i) {
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
        snprintf(string, len, "%s", "Unkown type");
        size = strlen(string);
      }
      break;

    default:
      fprintf(stderr, "WARN: while converting REXP to string, unimplemented type.\n");
      string = calloc(1, sizeof(char));
      break;
  }

  return realloc(string, size + 1);
}

void rexp_print(const REXP *rx)
{
  char *const s = rexp_to_string(rx, " ");
  puts(s);
  free(s);
}

bool rexp_equals(const REXP *rx, const REXP *ry)
{
  assert(rx);
  assert(ry);

  if (rx->type != ry->type) return false;

  switch (rx->type) {
    case XT_NULL:
      if (ry->data) return false;
      break;

    case XT_ARRAY_DOUBLE:
      double *xd = (double *)rx->data, *yd = (double *)ry->data, tol = 1e-10;
      if (cvector_size(xd) != cvector_size(yd)) return false;
      for (size_t i = 0; i < cvector_size(xd); ++i) {
        // x != x is only true if x = nan
        if (!(xd[i] != xd[i] && yd[i] != yd[i]) &&
            !(xd[i] - yd[i] > -tol && xd[i] - yd[i] < tol)) return false;
      }
      break;

    case XT_ARRAY_INT:
      int *xi = (int *)rx->data, *yi = (int *)ry->data;
      if (cvector_size(xi) != cvector_size(yi)) return false;
      for (size_t i = 0; i < cvector_size(xi); ++i) {
        if (xi[i] != yi[i]) return false;
      }
      break;

    case XT_ARRAY_BOOL: case XT_RAW:
      char *xb = (char *)rx->data, *yb = (char *)ry->data;
      if (cvector_size(xb) != cvector_size(yb)) return false;
      for (size_t i = 0; i < cvector_size(xb); ++i) {
        if (xb[i] != yb[i]) return false;
      }
      break;

    case XT_ARRAY_STR:
      char **xs = (char **)rx->data, **ys = (char **)ry->data;
      if (cvector_size(xs) != cvector_size(ys)) return false;
      for (size_t i = 0; i < cvector_size(xs); ++i) {
        if (xs[i] == NULL || ys[i] == NULL) {
          if (xs[i] != NULL || ys[i] != NULL) return false;
        } else {
          if (strcmp(xs[i], ys[i]) != 0) return false;
        }
      }
      break;

    case XT_STR: case XT_SYMNAME:
      if (rx->data == NULL || ry->data == NULL) {
        if (rx->data != NULL || ry->data != NULL) return false;
      } else {
        if (strcmp((char *)rx->data, (char *)rx->data) != 0) return false;
      }
      break;

    case XT_LIST_TAG: case XT_LIST_NOTAG:
    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_VECTOR: case XT_VECTOR_EXP:
      char *sx, *sy;
      REXP *x, *y;
      RList *xl = (RList *)rx->data, *yl = (RList *)ry->data;
      if (rlist_size(xl) != rlist_size(xl)) return false;
      for (size_t i = 0; i < rlist_size(xl); ++i) {
        x = rlist_at(xl, i);
        y = rlist_at(yl, i);
        if (!rexp_equals(x, y)) return false;
        if (rx->type ==  XT_LIST_TAG || rx->type ==  XT_LANG_TAG) {
          sx = rlist_name_at(xl, i);
          sy = rlist_name_at(yl, i);
          if (sx == NULL || sy == NULL) {
            if (sx != NULL || sy != NULL) return false;
          } else {
            if (strcmp(sx, sy) != 0) return false;
          }
        }
      }
      break;

    case XT_UNKNOWN:
      fprintf(stderr, "WARN: while comparing REXPs, unknown type.\n");
      return false;

    default:
      fprintf(stderr, "WARN: while comparing REXPs, unimplemented type.\n");
      return false;
  }

  return true;
}

int rexp_binlen(const REXP *rx)
{
  assert(rx);

  int len = 0;

  if (rx->attr) len += rexp_binlen(rx->attr);

  switch (rx->type) {
    case XT_NULL:
      break;

    case XT_ARRAY_INT:
      len = cvector_size((int *)rx->data) * 4;
      break;

    case XT_ARRAY_DOUBLE:
      len = cvector_size((double *)rx->data) * 8;
      break;

    case XT_ARRAY_BOOL: case XT_RAW:
      len = cvector_size((char *)rx->data) + 4;
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_ARRAY_STR:
      char **strings = (char **)rx->data;
      for (size_t i = 0; i < cvector_size((char **)rx->data); ++i) {
        if (strings[i] == NULL) {
          len++;
        } else {
          len += strlen(strings[i]);
        }
        len++;
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
        if (rx->type ==  XT_LANG_TAG || rx->type ==  XT_LIST_TAG) {
          char *s = rlist_name_at(rx->data, i);
          len += 4; // header for a symbol
          len += (s == NULL) ? 1 : strlen(s) + 1;
          if ((len & 3) > 0) len = len - (len & 3) + 4;
        }
      }
      if ((len & 3) > 0) len = len - (len & 3) + 4;
      break;

    case XT_UNKNOWN:
      fprintf(stderr, "WARN: while computing REXP bin length, unknown type.\n");
      return len;

    default:
      fprintf(stderr, "WARN: while computing REXP bin length, unimplemented type.\n");
      return len;
  }

  // Return len after adding space for the expression header
  return (len > 0xfffff0) ? len + 8 : len + 4;
}

int rexp_encode(const REXP *rx, char *buf, int rxo, int len) 
{
  assert(rx);

  int hdrlen = (len > 0xfffff0) ? 8 : 4, stringlen, start = rxo, rxi;

  set_hdr(rx->type | (rx->attr ? XT_HAS_ATTR : 0), len - hdrlen, buf, rxo);

  rxo += hdrlen;

  if (rx->attr) rxo = rexp_encode(rx->attr, buf, rxo, rexp_binlen(rx->attr));

  switch (rx->type) {
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
        buf[rxi++] = b == LGL_NA ? 2 : (b == LGL_FALSE ? 0 : 1);
      }
      while ((rxi & 3) != 0) buf[rxi++] = 0xff;
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
        if (strings[i] == NULL) {
          buf[rxi++] = -1;
        } else {
          stringlen = strlen(strings[i]);
          memcpy(buf + rxi, strings[i], stringlen);
          rxi += stringlen;
        }
        buf[rxi++] = 0;
      }
      while (((rxi - rxo) & 3) != 0) buf[rxi++] = 1;
      break;

   case XT_STR: case XT_SYMNAME:
      char *string = rx->data ? rx->data : "";
      rxi = rxo;
      stringlen = strlen(string);
      memcpy(buf + rxi, string, stringlen);
      rxi += stringlen;
      buf[++rxi] = 0;
      while ((rxi & 3) != 0) buf[rxi++] = 0;
      break;

    case XT_LANG_TAG: case XT_LANG_NOTAG:
    case XT_LIST_TAG: case XT_LIST_NOTAG:
    case XT_VECTOR: case XT_VECTOR_EXP:
      RList *list = rx->data;
      REXP *x;
      rxi = rxo;
      for (size_t i = 0; i < rlist_size(list); ++i) {
        x = rlist_at(list, i);
        if (x == NULL) x = &(REXP) { XT_NULL, 0, 0 };
        rxi = rexp_encode(x, buf, rxi, rexp_binlen(x));
        if (rx->type == XT_LANG_TAG ||rx->type == XT_LIST_TAG) {
          x = &(REXP) { XT_SYMNAME, rlist_name_at(list, i), 0 };
          rxi = rexp_encode(x, buf, rxi, rexp_binlen(x));
        }
      }
      break;

    case XT_UNKNOWN:
      fprintf(stderr, "ERROR: cannot encode REXP of type XT_UNKNOWN.\n");
      return -1;

    default:
      fprintf(stderr, "ERROR: cannot encode unimplemented REXP type.\n");
      return -1;
  }

  return start + len;
}
