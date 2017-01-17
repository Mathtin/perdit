#ifndef _BYTECONVERT_H_
#define _BYTECONVERT_H_

#if defined(_WIN32) || defined(__CYGWIN__)
#define WIN32_LEAN_AND_MEAN
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define TYP_INIT 0
#define TYP_SMLE 1
#define TYP_BIGE 2

#ifdef __cplusplus
extern "C"
#endif
    unsigned long long
    htonll(unsigned long long src);

#ifdef __cplusplus
extern "C"
#endif
    unsigned long long
    ntohll(unsigned long long src);

#endif
