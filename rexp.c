#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "cvector.h"
#include "rexp.h"
#include "rserve.h"

extern int get_len(char* y, size_t o);
extern void set_int(int32_t x, char* y, size_t o);
extern int get_int(char* y, size_t o);
extern void set_long(int64_t x, char* y, size_t o);
extern long get_long(char* y, size_t o);

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
    case XT_NULL:
      break;
  }
}

bool rexp_is_symbol(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return false;
    case XT_INT: case XT_ARRAY_INT:
      return false;
    case XT_NULL:
      return false;
    default:
      return false;
  }
}

bool rexp_is_vector(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return true;
    case XT_INT: case XT_ARRAY_INT:
      return true;
    case XT_NULL:
      return false;
    default:
      return false;
  }
}

bool rexp_is_list(REXP *rx)
{
  assert(rx);

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      return false;
    case XT_INT: case XT_ARRAY_INT:
      return false;
    case XT_NULL:
      return false;
    default:
      return false;
  }
}

int rexp_parse(REXP *rx, char *buf, int rxo)
{
  assert(rx);
  assert(buf);

  int rxl, eox;
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
    rxo = rexp_parse(rx->attr, buf, rxo);
  }

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      cvector(double) doubles = NULL;
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
      int i;
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

    case XT_NULL:
      break;
  }

  return rxo;
}

char *rexp_to_string(REXP *rx, char *sep)
{
  assert(rx);
  assert(sep);

  size_t seplen = strlen(sep), len = 100 + seplen, capacity = 10 * len, size = 0;
  char *string = calloc(capacity, sizeof(char));

  switch(rx->type) {
    case XT_DOUBLE: case XT_ARRAY_DOUBLE:
      if (string) {
        snprintf(string, len, "%f", *(double *)rx->data);
        size = strlen(string);
        for (size_t i = 1; i < cvector_size((double *)rx->data); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          snprintf(string + strlen(string), len, "%f", *((double *)rx->data + i));
          size = strlen(string);
        }
      }
      break;

    case XT_INT: case XT_ARRAY_INT:
      if (string) {
        if (NA_INTERNAL == *(int *)rx->data) {
          snprintf(string, len, "%s", "NA");
        } else {
          snprintf(string, len, "%d", *(int *)rx->data);
        }
        size = strlen(string);
        for (size_t i = 1; i < cvector_size((int *)rx->data); ++i) {
          if (capacity - size < len + strlen(sep)) {
            if ((string = realloc(string, capacity *= 2))) {
              memset(string, 0, capacity);
            } else {
              break;
            }
          }
          strcat(string, sep);
          if (NA_INTERNAL == *((int *)rx->data + i)) {
            snprintf(string + strlen(string), len, "%s", "NA");
          } else {
            snprintf(string + strlen(string), len, "%d", *((int *)rx->data + i));
          }
          size = strlen(string);
        }
      }
      break;


    case XT_NULL:
      snprintf(string, len, "%s", "NULL");
      size = strlen(string);
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
