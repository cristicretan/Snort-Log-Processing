#ifndef __SNORTDB_H__
#define __SNORTDB_H__

#include "u2spewfoo.h"
#include <stdlib.h>
#include <mysql/mysql.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int u2_to_db(char *file, MYSQL *con);
void finish_with_error(MYSQL *con);
#endif
