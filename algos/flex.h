#ifndef FLEX_H
#define FLEX_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void flex_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif
#endif
