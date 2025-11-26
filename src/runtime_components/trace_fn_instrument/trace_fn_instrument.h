#ifndef TRACE_FN_INSTRUMENT_H
#define TRACE_FN_INSTRUMENT_H

#include <stdint.h>

#define NO_INSTRUMENT __attribute__((no_instrument_function))

#ifdef __cplusplus
extern "C" {
#endif

void trace_fn_init(void) NO_INSTRUMENT;
void trace_fn_shutdown(void) NO_INSTRUMENT;
// Dump the traced function call information to the specified file path
void trace_fn_dump(const char *path) NO_INSTRUMENT;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // TRACE_FN_INSTRUMENT_H