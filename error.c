/* Authors: Andrew Allen, Berck Nash
   Class: Computer Architecture, Spring 2012
   file: error.c

   Error-handling functions
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void error(char *string)
{
     if (errno) {
	  fprintf(stderr, "\n***%s\n\t%s\n", string, strerror(errno));
	  errno = 0;
     }
     else
	  fprintf(stderr, "\n***%s\n", string);
}

void fatal(char *string)
{
     if (errno) {
	  fprintf(stderr, "\n%s\n\t%s\n", string, strerror(errno));
	  errno = 0;
     }
     else
	  fprintf(stderr, "\n%s\n", string);
     exit(1);
}
