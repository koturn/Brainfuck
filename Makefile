### This Makefile was written for GNU Make. ###
ifeq ($(OPT),true)
	COPTFLAGS  := -flto -Ofast -mtune=native -march=native -DNDEBUG
	LDOPTFLAGS := -flto -Ofast -s
else
ifeq ($(DEBUG),true)
	COPTFLAGS  := -O0 -g3 -ftrapv -fstack-protector-all -D_FORTIFY_SOURCE=2
	LDLIBS     := -lssp
else
	COPTFLAGS  := -O3 -DNDEBUG
	LDOPTFLAGS := -O3 -s
endif
endif
C_WARNING_FLAGS := -Wall -Wextra -Wformat=2 -Wstrict-aliasing=2 \
                   -Wcast-align -Wcast-qual -Wconversion \
                   -Wfloat-equal -Wpointer-arith -Wswitch-enum \
                   -Wwrite-strings -pedantic
MAX_SOURCE_SIZE   ?= 65536
MAX_BYTECODE_SIZE ?= 1048576
JUMP_STACK_SIZE   ?= 256
MEMORY_SIZE       ?= 65536
BF_ADDR_INT       ?= 'unsigned int'
BF_SEEK_INT       ?= 'unsigned short'
BF_INT            ?= 'unsigned char'
INDENT_STR        ?= '"  "'
MACROS ?= -DMAX_SOURCE_SIZE=$(MAX_SOURCE_SIZE) \
          -DMAX_BYTECODE_SIZE=$(MAX_BYTECODE_SIZE) \
          -DJUMP_STACK_SIZE=$(JUMP_STACK_SIZE) \
          -DMEMORY_SIZE=$(MEMORY_SIZE) \
          -DBF_ADDR_INT=$(BF_ADDR_INT) \
          -DBF_INT=$(BF_INT) \
          -DINDENT_STR=$(INDENT_STR)

CC      := gcc
CFLAGS  := -pipe $(C_WARNING_FLAGS) $(COPTFLAGS) $(MACROS)
LDFLAGS := -pipe $(LDOPTFLAGS)
TARGET  := brainfuck
OBJ     := $(addsuffix .o, $(basename $(TARGET)))
SRC     := $(OBJ:%.o=%.c)

ifeq ($(OS),Windows_NT)
    TARGET := $(addsuffix .exe, $(TARGET))
else
    TARGET := $(addsuffix .out, $(TARGET))
endif


%.exe:
	$(CC) $(LDFLAGS) $(filter %.c %.o, $^) $(LDLIBS) -o $@
%.out:
	$(CC) $(LDFLAGS) $(filter %.c %.o, $^) $(LDLIBS) -o $@


.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJ)

$(OBJ): $(SRC)


.PHONY: test
test:
	./$(TARGET) -h


.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJ)
.PHONY: cleanobj
cleanobj:
	$(RM) $(OBJ)
