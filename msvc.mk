### This Makefile was written for nmake. ###
MSVC_MACROS = /D_CRT_SECURE_NO_WARNINGS /D_SECURE_SCL=0

GETOPT_DIR        = getopt
GETOPT_REPOSITORY = https://github.com/koturn/$(GETOPT_DIR).git
GETOPT_LIBS_DIR   = $(GETOPT_DIR)/lib
GETOPT_LIB        = getopt.lib
GETOPT_LDLIBS     = /link /LIBPATH:$(GETOPT_LIBS_DIR) $(GETOPT_LIB)
GETOPT_INCS       = /Igetopt/include/

MAX_SOURCE_SIZE   = 65536
MAX_BYTECODE_SIZE = 1048576
JUMP_STACK_SIZE   = 256
MEMORY_SIZE       = 65536
BF_ADDR_INT       = "unsigned int"
BF_SEEK_INT       = "unsigned short"
BF_INT            = "unsigned char"
INDENT_STR        = "\"  \""

MACROS = $(MSVC_MACROS) \
         /DMAX_SOURCE_SIZE=$(MAX_SOURCE_SIZE) \
         /DMAX_BYTECODE_SIZE=$(MAX_BYTECODE_SIZE) \
         /DJUMP_STACK_SIZE=$(JUMP_STACK_SIZE) \
         /DMEMORY_SIZE=$(MEMORY_SIZE) \
         /DBF_ADDR_INT=$(BF_ADDR_INT) \
         /DBF_INT=$(BF_INT) \
         /DINDENT_STR=$(INDENT_STR)

CC       = cl
RM       = del /F
MAKE     = $(MAKE) /nologo
GIT      = git
INCS     = $(GETOPT_INCS)
CFLAGS   = /nologo /O2 /W4 /EHsc /c $(INCS) $(MACROS)
LDFLAGS  = /nologo /O2
LDLIBS   = $(GETOPT_LDLIBS)
TARGET   = brainfuck.exe
OBJ      = $(TARGET:.exe=.obj)
SRC      = $(TARGET:.exe=.c)
MAKEFILE = msvc.mk


.SUFFIXES: .c .obj .exe
.obj.exe:
	$(CC) $(LDFLAGS) $** /Fe$@ $(LDLIBS)
.c.obj:
	$(CC) $(CFLAGS) $** /Fo$@


all: $(GETOPT_LIBS_DIR)/$(GETOPT_LIB) $(TARGET)

$(TARGET): $(OBJ)

$(OBJ): $(SRC)

$(GETOPT_LIBS_DIR)/$(GETOPT_LIB):
	@if not exist $(@D)\NUL \
	    $(GIT) clone $(GETOPT_REPOSITORY)
	cd $(GETOPT_DIR)  &  $(MAKE) /f $(MAKEFILE)  &  cd $(MAKEDIR)


clean:
	$(RM) $(TARGET) $(OBJ)
cleanobj:
	$(RM) $(OBJ)
