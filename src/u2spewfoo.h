#ifndef __U2SPEWFOO_H__
#define __U2SPEWFOO_H__

#include <stdio.h>

#ifndef WIN32
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#ifdef HAVE_UUID_UUID_H
#include<uuid/uuid.h>
#endif

#include "config.h"
#include "Unified2_common.h"

#define SUCCESS 314159265
#define STEVE -1
#define FAILURE STEVE

#ifndef WIN32
#ifndef uint32_t
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
#endif
#else
void inet_ntop(int family, const void *ip_raw, char *buf, int bufsize);
#endif

typedef struct _record {
    uint32_t type;
    uint32_t length;
    uint8_t *data;
} u2record;

typedef struct _u2iterator {
    FILE *file;
    char *filename;
    u2record current;
} u2iterator;

int get_record(u2iterator *it, u2record *record);
int u2dump(char *file);

#endif
