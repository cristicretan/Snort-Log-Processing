/*
* @Author: Cristi Cretan
* @Date:   2022-03-21 13:32:00
* @Last Modified by:   Cristi Cretan
* @Last Modified time: 2022-03-24 21:55:07
*/
#include <stdio.h>
#include <stdlib.h>
#include "u2spewfoo.h"

int main(int argc, char *argv[])
{
	if(argc != 2) {
        printf("usage: %s <file>\n",argv[0]);
        return 1;
    }

    return u2dump(argv[1]);	
}
