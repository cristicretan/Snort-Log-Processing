/*
* @Author: Cristi Cretan
* @Date:   2022-03-21 13:32:00
* @Last Modified by:   Cristi Cretan
* @Last Modified time: 2022-03-27 22:12:44
*/
#include <stdio.h>
#include <stdlib.h>
#include "u2spewfoo.h"
#include "snortdb.h"

int main(int argc, char *argv[])
{
	if(argc != 2) {
        printf("usage: %s <file>\n",argv[0]);
        return 1;
    }

    MYSQL *con = mysql_init(NULL);
    if (con == NULL) {
    	finish_with_error(con);
    }

    if (mysql_real_connect(con, "localhost", "root", "11jk13unQ1$", "snortdb", 0, NULL, 0) == NULL) {
    	finish_with_error(con);
    }

    u2_to_db(argv[1], con);
    mysql_close(con);

    return 0;
}
