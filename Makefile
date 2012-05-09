#   Authors: Berck E. Nash, Eli Ricca
#   Class: Computer Architecture, Spring 2012
#   File: Makefile
#
#   Makefile used to compile the CCM implementation.

TARGET  := ccm
SRCS    := ccm.c error.c main.c
OBJS    := ${SRCS:.c=.o}
DEPS    := ${SRCS:.c=.dep}
XDEPS   := $(wildcard ${DEPS})

CC = gcc
CCFLAGS = -Wall -O2
LDFLAGS = -lcrypto
LIBS    =

.PHONY: all clean debug
all:: ${TARGET}

debug: CCFLAGS = -DDEBUG -ggdb -Wall
debug: ${TARGET}

ifneq (${XDEPS},)
include ${XDEPS}
endif

${TARGET}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ $^ ${LIBS}

${OBJS}: %.o: %.c %.dep
	${CC} ${CCFLAGS} -o $@ -c $<

${DEPS}: %.dep: %.c Makefile
	${CC} ${CCFLAGS} -MM $< > $@

test::
	./test.sh

clean::
	-rm -f *~ *.o ${TARGET}
