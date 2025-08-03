#ifndef REXP_H_ 
#define REXP_H_

#include <stdbool.h>
#include <stddef.h>

#define NA_INTERNAL -2147483648

#define REXP_ERROR -1
#define REXP_SUCCESS 0

typedef enum
{
  XT_NULL          = 0,
  //XT_INT           = 1,
  XT_DOUBLE        = 2,
  //XT_STR           = 3,
  //XT_LANG          = 4,
  //XT_SYM           = 5,
  //XT_LOGICAL       = 6,
  //XT_S4            = 7,
  //XT_VECTOR        = 16,
  //XT_LIST          = 17,
  //XT_CLOS          = 18,
  //XT_SYMNAME       = 19,
  //XT_LIST_NOTAG    = 20,
  //XT_LIST_TAG      = 21,
  //XT_LANG_NOTAG    = 22,
  //XT_LANG_TAG      = 23,
  //XT_VECTOR_EXP    = 26,
  //XT_VECTOR_STR    = 27,
  //XT_ARRAY_INT     = 32,
  XT_ARRAY_DOUBLE  = 33,
  //XT_ARRAY_STR     = 34,
  //XT_ARRAY_BOOL_UA = 35,
  //XT_ARRAY_BOOL    = 36,
  //XT_RAW           = 37,
  //XT_ARRAY_CPLX    = 38,
  //XT_UNKNOWN       = 48,
  //XT_FACTOR        = 127,
  //XT_HAS_ATTR      = 128
} REXPType;

typedef struct REXP {
  REXPType type;
  void *data;
  struct REXP *attr;
} REXP;

void rexp_free(REXP *rx);
void rexp_clear(REXP *rx);
bool rexp_is_string(REXP *rx);
bool rexp_is_symbol(REXP *rx);
bool rexp_is_vector(REXP *rx);
bool rexp_is_list(REXP *rx);
char *rexp_to_string(REXP *rx, char *sep);
void rexp_print(REXP *rx);
int rexp_parse(REXP *rx, char *buf, int rxo);

#endif // REXP_H_
