CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lgmp

# Nombre del ejecutable
TARGET = main.exe

# Archivos fuente
SRCS = main.c elipt_curve.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	cp $(TARGET) lab02.exe

clean:
	rm -f $(TARGET) lab02.exe *.o

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
