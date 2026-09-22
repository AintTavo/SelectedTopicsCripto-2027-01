CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lgmp
TARGET = main.exe

all: $(TARGET)

$(TARGET): main.c elipt_curve.c elipt_curve.h
	$(CC) $(CFLAGS) main.c elipt_curve.c -o $(TARGET) $(LIBS)
	cp $(TARGET) lab01.exe

clean:
	rm -f $(TARGET) lab01.exe *.o

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
