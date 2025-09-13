#ifndef REXP_H_ 
#define REXP_H_

#include <stdbool.h>
#include <stddef.h>

#define NA_INTERNAL -2147483648

#define REXP_ERROR -1
#define REXP_SUCCESS 0

typedef enum {
  FALSE = 0,
  TRUE  = 1,
  NA    = -128,
} RLogical;

typedef enum
{
  XT_NULL          = 0,
  XT_STR           = 3,
  //XT_S4            = 7,
  XT_VECTOR        = 16,
  //XT_CLOS          = 18,
  XT_SYMNAME       = 19,
  XT_LIST_NOTAG    = 20,
  XT_LIST_TAG      = 21,
  XT_LANG_NOTAG    = 22,
  XT_LANG_TAG      = 23,
  XT_VECTOR_EXP    = 26,
  XT_ARRAY_INT     = 32,
  XT_ARRAY_DOUBLE  = 33,
  XT_ARRAY_STR     = 34,
  XT_ARRAY_BOOL    = 36,
  XT_RAW           = 37,
  //XT_ARRAY_CPLX    = 38,
  XT_UNKNOWN       = 48,
  //XT_FACTOR        = 127,
} REXPType;

#define XT_HAS_ATTR 128

typedef struct REXP {
  REXPType type;
  void *data;
  struct REXP *attr;
} REXP;

void rexp_free(REXP *rx);
void rexp_clear(REXP *rx);
REXP *rexp_copy(REXP *ry, REXP *rx);
bool rexp_is_string(REXP *rx);
bool rexp_is_vector(REXP *rx);
bool rexp_is_list(REXP *rx);
bool rexp_equals(REXP *rx, REXP *ry);
int rexp_binlen(REXP *rx);
int rexp_encode(REXP *rx, char *buf, int rxo, int len);
int rexp_decode(REXP *rx, char *buf, int rxo);
char *rexp_to_string(REXP *rx, char *sep);
void rexp_print(REXP *rx);

#endif // REXP_H_
