CC = gcc
AR = ar
FLAGS = -Wall -g

all: sender&reciver

sender&reciver: FileSender&Reciver
	$(CC) -o FileSender&Reciver FileSender&Reciver.c
clean:
	rm -f *.o *.txt *.client *.server FileSender&Reciver 