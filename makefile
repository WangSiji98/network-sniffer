CC=g++
CFLAGS= -lpcap -std=c++11
TARGET=main
SRCS = main.cpp ./src/sniffer.cpp ./src/capture.cpp ./src/capture_qq.cpp

INC = -I ./include

OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
		$(CC) -o $@ $^ $(CFLAGS)

clean:
		rm -rf $(TARGET)

%.o:%.c
		$(CC) $(CFLAGS) $(INC) -o $@ -c $<
