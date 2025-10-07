#include "cvector.h"
#include "rlist.h"

void rawrexp_init(REXP *raw, char *start, char *end)
{
  assert(raw);
  assert(raw->data == NULL);

  cvector(char) bytes = NULL;
  cvector_reserve(bytes, (size_t)(end - start));

  while (start != end) cvector_push_back(bytes, *start++);

  raw->type = XT_RAW;
  raw->data = bytes;
}

size_t rawrexp_size(const REXP *raw)
{
  assert(raw);
  assert(raw->data);
  assert(raw->type == XT_RAW);

  return cvector_size((char *)raw->data);
}

void assign_call(REXP *call, const REXP *capability, const REXP *args, size_t nargs)
{
  assert(call);
  assert(capability);
  assert(call->data == NULL);

  REXP ocap = { 0 };
  RList *rl = malloc(sizeof(RList));

  rexp_copy(&ocap, capability);

  rlist_init(rl, nargs + 1, false);
  rlist_add(rl, ocap);
  for (size_t i = 0; i < nargs; ++i) rlist_add(rl, args[i]);
  call->type = XT_LANG_NOTAG;
  call->data = rl;
}
