FLAGS  = -Wall -g
CC     = gcc
PROG   = des
OBJS   = DES.o main.o

all:	${PROG}

clean:
	rm ${OBJS}
  
${PROG}:	${OBJS}
	${CC} ${FLAGS} ${OBJS} -o $@

.c.o:
	${CC} ${FLAGS} $< -c

##########################

main.o:  main.c

DES.o: DES.h DES.c
