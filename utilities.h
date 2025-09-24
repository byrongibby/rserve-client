#ifndef UTILITIES_H_ 
#define UTILITIES_H_

#include "rexp.h"

/* Copy bytes from start to end to raw REXP (XT_RAW)
 */
void rawrexp_init(REXP *raw, char *start, char *end);

/* return the size of raw REXP (XT_RAW)
 */
size_t rawrexp_size(const REXP *raw);

/* Takes in an Rserve ocap with args array and transfers ownership
 * to a call REXP (XT_LANG_NOTAG), which is used as an argument to
 * rserve_callocap()
 */
void assign_call(REXP *call, REXP *capability, REXP *args, size_t nargs);


#endif /* UTILITIES_H_ */
