CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lgmp

# Nombre del ejecutable principal
TARGET = main.exe

# Archivos fuente
SRCS = main.c ecdsa.c ellipticcurve/elipt_curve.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	cp $(TARGET) lab03.exe

clean:
	rm -f $(TARGET) lab03.exe *.o ellipticcurve/*.o public_key.txt private_key.txt firma.txt

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
