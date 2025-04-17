CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -pthread

# Source and object files
SRC_DIR = src
INCLUDE_DIR = include
TEST_DIR = test

LIB_SRC = $(SRC_DIR)/geneve.c
LIB_OBJ = $(LIB_SRC:.c=.o)

TEST_IPV4 = $(TEST_DIR)/geneve_test4.c
TEST_IPV6 = $(TEST_DIR)/geneve_test6.c

TEST_IPV4_EXE = geneve_test4
TEST_IPV6_EXE = geneve_test6

.PHONY: all clean

all: $(TEST_IPV4_EXE) $(TEST_IPV6_EXE)

$(TEST_IPV4_EXE): $(TEST_IPV4) $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_IPV6_EXE): $(TEST_IPV6) $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(LIB_OBJ): $(LIB_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRC_DIR)/*.o $(TEST_IPV4_EXE) $(TEST_IPV6_EXE)
