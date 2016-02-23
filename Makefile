CC=clang
SHELL=sh
CFLAGS=-Wall -Wextra -Wno-unused-parameter -pedantic -std=c11 -g $(PKGFLAGS)
PKGFLAGS=`pkg-config fuse --cflags --libs`
MNT_DIR=mnt
TARGET=fat

all: $(TARGET)

clean: unmount
	rm -f $(TARGET)
	-rmdir $(MNT_DIR)

unmount:
	-fusermount -u $(MNT_DIR)

# debug mount 
dmount: $(TARGET) $(MNT_DIR) unmount
	./$(TARGET) -s -f -d $(MNT_DIR)

mount: $(TARGET) $(MNT_DIR) unmount
	./$(TARGET) -s $(MNT_DIR)

$(MNT_DIR):
	mkdir -p $(MNT_DIR)
