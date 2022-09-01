.SUFFIXES: .o

LDFLAGS := -shared -L. -lstrace -ldl

TARGET := libsbox.so
STRIP := strip

%.o : %.c
	$(CC) $(CFLAGS) -o $@ $^

OBJS := sandbox.o

all: $(OBJS)
	$(LD) $(LDFLAGS) -o $(TARGET) $^
	$(STRIP) $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean
