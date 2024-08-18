// Using this header is completely optional

#ifndef CGOLDIE_H
#define CGOLDIE_H

#include <stddef.h>
#include <stdint.h>

#ifndef CGOLDIE_TESTS
#define CGOLDIE_TESTS 1
#endif

void cgoldie(uint8_t ss[56], const uint8_t k[56], const uint8_t u[56]);

#if CGOLDIE_TESTS != 0
size_t cgoldie_test(void);
#endif

#endif
