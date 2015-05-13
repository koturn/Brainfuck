/*!
 * @file brainfuck.c
 * @brief An interpreter and translator of Brainfuck
 * @author koturn
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if (defined(_MSC_VER) && _MSC_VER >= 1600) || \
      (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
#  include <stdint.h>
#endif

#if defined(_WIN32) || defined(_WIN64) || (defined(__CYGWIN__) && defined(__x86_64__))
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN_IS_NOT_DEFINED
#  endif
#  include <windows.h>
#  ifdef LEAN_AND_MEAN_IS_NOT_DEFINED
#    undef LEAN_AND_MEAN_IS_NOT_DEFINED
#    undef WIN32_LEAN_AND_MEAN
#  endif
#elif defined(__linux__)
#  include <unistd.h>
#  include <sys/mman.h>
#endif



#include <getopt.h>
#if defined(_MSC_VER) && defined(_DEBUG)
#  include <msvcdbg.h>
#endif

#ifndef MAX_SOURCE_SIZE
#  define MAX_SOURCE_SIZE  65536
#endif
#ifndef MAX_BYTECODE_SIZE
#  define MAX_BYTECODE_SIZE  1048576
#endif
#ifndef JUMP_STACK_SIZE
#  define JUMP_STACK_SIZE  256
#endif
#ifndef MEMORY_SIZE
#  define MEMORY_SIZE  65536
#endif
#ifndef BF_ADDR_INT
#  define BF_ADDR_INT  size_t
#endif
#ifndef BF_SEEK_INT
#  define BF_SEEK_INT  unsigned short
#endif
#ifndef BF_INT
#  define BF_INT  unsigned char
#endif
#ifndef INDENT_STR
#  define INDENT_STR  "  "
#endif

#if (defined(_MSC_VER) && _MSC_VER >= 1600) || \
      (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L)
#  ifndef INT32_T
#    define INT32_T  int32_t
#  endif
#  ifndef UINT8_T
#    define UINT8_T  uint8_t
#  endif
#else
#  ifndef INT32_T
#    define INT32_T  int
#  endif
#  ifndef UINT8_T
#    define UINT8_T  unsigned char
#  endif
#endif

#define TRUE   1
#define FALSE  0
#define LENGTHOF(array)  (sizeof(array) / sizeof((array)[0]))
#define ADDR_DIFF(a, b) \
  ((const unsigned char *) (a) - (const unsigned char *) (b))
#define ASSIGN_AS(type, ptr, val) \
  *((type *) (ptr)) = (type) (val)

#if defined(_WIN64) || defined(__MINGW64__) || (defined(__CYGWIN__) && defined(__x86_64__))
#  define IS_X64_WIN
#elif defined(__x86_64__)
#  define IS_X64_GCC
#endif
#if !defined(IS_X64) && !defined(IS_X86)
#  if defined(IS_X64_GCC) || defined(IS_X64_WIN)
#    define IS_X64
#  else
#    define IS_X86
#  endif
#endif
#if defined(IS_X86) || defined(IS_X64_WIN)
#  define JMP_OFFSET  7
#else
#  define JMP_OFFSET  8
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */


enum ErrorCode {
  BF_NO_ERROR,
  LOOP_START_ERROR,
  LOOP_END_ERROR
};

enum OpCode {
  HALT = 0x00,
  PTR_ADD = '>', PTR_SUB = '<',
  ADD = '+', SUB = '-',
  PUT_CHAR = '.', READ_CHAR = ',',
  LOOP_START = '[', LOOP_END = ']',
  ASSIGN_ZERO
};

typedef struct {
  const char *in_filename;
  const char *out_filename;
  const char *one_line_code;
  int mode;
} Param;

typedef BF_ADDR_INT  BfAddrInt;
typedef BF_SEEK_INT  BfSeekInt;
typedef BF_INT  BfInt;
typedef INT32_T  bf_int32_t;
typedef UINT8_T  bf_uint8_t;


static void
parse_arguments(Param *param, int argc, char *argv[]);

static void
show_usage(const char *progname);

static int
read_file(FILE *fp, char *code, size_t length);

static int
interpret_exec(const char *code);

static void
execute(const unsigned char *bytecode);

static void
jit_execute(unsigned char *bin, size_t bin_size);

static int
compile(unsigned char *bytecode, size_t *bytecode_size, const char *code);

static int
jit_compile(unsigned char *bin, size_t *bin_size, const char *code);

static int
translate(FILE *fp, const char *code);

static const char *
find_loop_end(const char *code);

static const char *
find_loop_start(const char *code);

static BfInt
count_char(const char *code, char ch);

static void
print_indent(FILE *fp, int depth);

static void
print_code_header(FILE *fp);

static void
print_code_footer(FILE *fp);

static void
show_bytecode(const unsigned char *bytecode, size_t bytecode_size);

static void
show_mnemonic(FILE *fp, const unsigned char *bytecode);




/*!
 * @brief Entry point of this program
 * @param [in] argc  The number of command-line arguments
 * @param [in] argv  Strings of command-line arguments
 * @return Exit-status
 */
int
main(int argc, char *argv[])
{
  static char code[MAX_SOURCE_SIZE];
#ifdef __linux__
  unsigned char *bytecode = mmap(0, MAX_BYTECODE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
  static unsigned char bytecode[MAX_BYTECODE_SIZE];
#endif
  const char *code_ptr;
  Param param = {NULL, NULL, NULL, 'c'};
  FILE *ifp, *ofp;
  int status = BF_NO_ERROR;
  size_t bytecode_size;
  if (bytecode == NULL) return 1;

  parse_arguments(&param, argc, argv);
  if (param.one_line_code == NULL) {
    if (param.in_filename == NULL) {
      fprintf(stderr, "Invalid arguments\n");
      return EXIT_FAILURE;
    }
    if (!strcmp(param.in_filename, "-")) {
      ifp = stdin;
    } else if ((ifp = fopen(param.in_filename, "r")) == NULL) {
      fprintf(stderr, "Unable to open file: %s\n", argv[1]);
      return EXIT_FAILURE;
    }
    if (!read_file(ifp, code, LENGTHOF(code))) {
      return EXIT_FAILURE;
    }
    if (ifp != stdin) {
      fclose(ifp);
    }
    code_ptr = code;
  } else {
    code_ptr = param.one_line_code;
  }

  switch (param.mode) {
    case 'b':
      if ((status = compile(bytecode, &bytecode_size, code_ptr)) != BF_NO_ERROR) {
        break;
      }
      show_bytecode(bytecode, bytecode_size);
      break;
    case 'c':
      if ((status = compile(bytecode, &bytecode_size, code_ptr)) != BF_NO_ERROR) {
        break;
      }
      execute(bytecode);
      break;
    case 'j':
      if ((status = jit_compile(bytecode, &bytecode_size, code_ptr)) != BF_NO_ERROR) {
        break;
      }
      jit_execute(bytecode, bytecode_size);
      break;
    case 'm':
      if ((status = compile(bytecode, &bytecode_size, code_ptr)) != BF_NO_ERROR) {
        break;
      }
      show_mnemonic(stdout, bytecode);
      break;
    case 'n':
      status = interpret_exec(code_ptr);
      break;
    case 't':
      if (param.out_filename == NULL) {
        translate(stdout, code_ptr);
      } else {
        if ((ofp = fopen(param.out_filename, "w")) == NULL) {
          fprintf(stderr, "Unable to open file: %s\n", param.out_filename);
          return EXIT_FAILURE;
        }
        translate(ofp, code_ptr);
        fclose(ofp);
      }
      break;
  }
  switch (status) {
    case LOOP_START_ERROR:
      fputs("Runtime error: unable find loop start\n", stderr);
      return EXIT_FAILURE;
    case LOOP_END_ERROR:
      fputs("Runtime error: unable find loop end\n", stderr);
      return EXIT_FAILURE;
  }
#ifdef __linux__
  munmap(bytecode, MAX_BYTECODE_SIZE);
#endif
  return EXIT_SUCCESS;
}


/*!
 * @brief Parse comamnd-line arguments and set parameters.
 *
 * 'argv' is sorted after called getopt_long().
 * @param [out]    param  Parameters of this program
 * @param [in]     argc   A number of command-line arguments
 * @param [in,out] argv   Coomand-line arguments
 * @return  Parameter structure of this program.
 */
static void
parse_arguments(Param *param, int argc, char *argv[])
{
  static const struct option opts[] = {
    {"bytecode",    no_argument,       NULL, 'b'},
    {"compile",     no_argument,       NULL, 'c'},
    {"execute",     required_argument, NULL, 'e'},
    {"help",        no_argument,       NULL, 'h'},
    {"jit-compile", no_argument,       NULL, 'j'},
    {"mnemonic",    no_argument,       NULL, 'm'},
    {"normal",      no_argument,       NULL, 'n'},
    {"output",      required_argument, NULL, 'o'},
    {"translate",   no_argument,       NULL, 't'},
    {0, 0, 0, 0}  /* must be filled with zero */
  };
  int ret;
  int optidx = 0;
  while ((ret = getopt_long(argc, argv, "bce:hjmno:t", opts, &optidx)) != -1) {
    switch (ret) {
      case 'b':  /* -b, --bytecode */
      case 'c':  /* -c, --compile */
      case 'j':  /* -j, --jit-compile */
      case 'm':  /* -m or --mnemonic */
      case 'n':  /* -n or --normal */
      case 't':  /* -t or --translate */
        param->mode = ret;
        break;
      case 'e':  /* -e */
        param->one_line_code = optarg;
        break;
      case 'h':  /* -h, --help */
        show_usage(argv[0]);
        exit(EXIT_SUCCESS);
      case 'o':  /* -o or --output */
        param->out_filename = optarg;
        break;
      case '?':  /* unknown option */
        show_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }
  if (optind != argc - 1 && param->one_line_code == NULL) {
    fputs("Please specify one brainfuck source code\n", stderr);
    show_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  param->in_filename = argv[optind];
}


/*!
 * @brief Show usage of this program and exit
 * @param [in] progname  A name of this program
 */
static void
show_usage(const char *progname)
{
  printf(
      "[Usage]\n"
      "  $ %s FILE [options]\n"
      "[Options]\n"
      "  -b, --bytecode\n"
      "    Show code in hexadecimal\n"
      "  -c, --compile (Default)\n"
      "    Compile brainfuck source code to VM code and run it\n"
      "  -e [CODE], --execute=[CODE]\n"
      "    Execute one line code\n"
      "  -h, --help\n"
      "    Show help and exit\n"
      "  -j, --jit-compile\n"
      "    Compile brainfuck to machine code and run it\n"
      "  -m, --mnemonic\n"
      "    Show byte code in mnemonic format\n"
      "  -n, --normal\n"
      "    Execute in normal mode (without optimization before execution)\n"
      "  -o FILE, --output=FILE\n"
      "    Specify output filename\n"
      "  -t, --translate\n"
      "    Translate brainfuck to C source code\n", progname);
}


/*!
 * @brief Store that source code from file to the buffer.
 *
 * When invalid characters are detected, then print error message and exit this
 * program.
 *
 * @param [in,out] fp      File pointer to brainfuck source code
 * @param [out]    code    Pointer to buffer you want to store brainfuck source code
 * @param [in]     length  The buffer size
 * @return  If invalid characters and detected or store source code beyond the
 *          buffer size, return 0. Oterwise return 1
 */
static int
read_file(FILE *fp, char *code, size_t length)
{
  int ch;
  size_t cnt = 0;
  for (; (ch = fgetc(fp)) != EOF; cnt++) {
    if (cnt > length) {
      fprintf(stderr, "Buffer overflow!\n");
      return FALSE;
    }
    switch (ch) {
      case '>':
      case '<':
      case '+':
      case '-':
      case '.':
      case ',':
      case '[':
      case ']':
        *code++ = (char) ch;
    }
  }
  return TRUE;
}


/*!
 * @brief Execute brainfuck without compile.
 * @param [in] code  Pointer to the brainfuck source code
 * @return  Status-code
 */
static int
interpret_exec(const char *code)
{
  static unsigned char memory[MEMORY_SIZE] = {0};
  unsigned char *ptr = memory;

  for (; *code != '\0'; code++) {
    switch (*code) {
      case '>': ptr++;            break;
      case '<': ptr--;            break;
      case '+': (*ptr)++;         break;
      case '-': (*ptr)--;         break;
      case '.': putchar(*ptr);    break;
      case ',': *ptr = getchar(); break;
      case '[':
        if (*ptr != 0) break;
        if ((code = find_loop_end(code)) == NULL) {
          return LOOP_END_ERROR;
        }
        break;
      case ']':
        if (*ptr == 0) break;
        if ((code = find_loop_start(code)) == NULL) {
          return LOOP_START_ERROR;
        }
        break;
    }
  }
  putchar('\n');
  return BF_NO_ERROR;
}


/*!
 * @brief Execute compiled brainfuck source code
 * @param [in] bytecode  Compiled brainfuck source code
 */
static void
execute(const unsigned char *bytecode)
{
  static unsigned char memory[MEMORY_SIZE] = {0};
  unsigned char *ptr = memory;
  const unsigned char *const base = bytecode;

  for (; *bytecode != HALT; bytecode++) {
    switch (*bytecode) {
      case PTR_ADD:
        bytecode++;
        ptr += *((const BfSeekInt *) bytecode);
        bytecode += sizeof(BfSeekInt) - 1;
        break;
      case PTR_SUB:
        bytecode++;
        ptr -= *((const BfSeekInt *) bytecode);
        bytecode += sizeof(BfSeekInt) - 1;
        break;
      case ADD:
        bytecode++;
        *ptr += *((const BfInt *) bytecode);
        bytecode += sizeof(BfInt) - 1;
        break;
      case SUB:
        bytecode++;
        *ptr -= *((const BfInt *) bytecode);
        bytecode += sizeof(BfInt) - 1;
        break;
      case PUT_CHAR:
        putchar(*ptr);
        break;
      case READ_CHAR:
        *ptr = getchar();
        break;
      case LOOP_START:
        if (*ptr == 0) {
          bytecode++;
          bytecode = &base[*((const BfAddrInt *) bytecode)] + sizeof(BfAddrInt);
        } else {
          bytecode += sizeof(BfAddrInt);
        }
        break;
      case LOOP_END:
        if (*ptr != 0) {
          bytecode++;
          bytecode = &base[*((const BfAddrInt *) bytecode)] - 1;
        } else {
          bytecode += sizeof(BfAddrInt);
        }
        break;
      case ASSIGN_ZERO:
        *ptr = 0;
        break;
    }
  }
  putchar('\n');
}


/*!
 * @brief Execute JIT-compiled Brainfuck code
 * @param [in] bin       JIT-compiled brainfuck code
 * @param [in] bin_size  Binary size of JIT-compiled brainfuck code
 */
static void
jit_execute(unsigned char *bin, size_t bin_size)
{
  static int stack[MEMORY_SIZE] = {0};
#if defined(_WIN32) || defined(_WIN64) || (defined(__CYGWIN__) && defined(__x86_64__))
  DWORD old_protect;
  VirtualProtect((LPVOID) bin, bin_size, PAGE_EXECUTE_READWRITE, &old_protect);
#elif defined(__linux__)
  long page_size = sysconf(_SC_PAGESIZE) - 1;
  if (mprotect((void *) bin, (bin_size + page_size) & ~page_size, PROT_READ | PROT_EXEC) == -1) {
    perror("mprotect");
    return;
  }
#endif
  ((void (*)(int (*)(int), int (*)(), int *)) (unsigned char *) bin)(putchar, getchar, stack);
}


/*!
 * @brief Compile brainfuck source code into bytecode
 * @param [out] bytecode       Bytecode buffer
 * @param [out] bytecode_size  Size of compiled brainfuck code
 * @param [in]  code           Brainfuck source code
 * @return Status-code
 */
static int
compile(unsigned char *bytecode, size_t *bytecode_size, const char *code)
{
  static unsigned char *stack[JUMP_STACK_SIZE];
  size_t stack_idx = 0;
  unsigned char *const base = bytecode;
  char ch = *code;
  BfInt cnt;
  for (ch = *code; ch != '\0'; ch = *++code) {
    switch (ch) {
      case '>':
        cnt = count_char(code, ch);
        code += cnt - 1;
        *bytecode++ = PTR_ADD;
        *((BfSeekInt *) bytecode) = cnt;
        bytecode += sizeof(BfSeekInt);
        break;
      case '<':
        cnt = count_char(code, ch);
        code += cnt - 1;
        *bytecode++ = PTR_SUB;
        *((BfSeekInt *) bytecode) = cnt;
        bytecode += sizeof(BfSeekInt);
        break;
      case '+':
        cnt = count_char(code, ch);
        code += cnt - 1;
        *bytecode++ = ADD;
        *((BfInt *) bytecode) = cnt;
        bytecode += sizeof(BfInt);
        break;
      case '-':
        cnt = count_char(code, ch);
        code += cnt - 1;
        *bytecode++ = SUB;
        *((BfInt *) bytecode) = cnt;
        bytecode += sizeof(BfInt);
        break;
      case '.':
        *bytecode++ = PUT_CHAR;
        break;
      case ',':
        *bytecode++ = READ_CHAR;
        break;
      case '[':
        if (code[1] == '-' && code[2] == ']') {
          code += 2;
          *bytecode++ = ASSIGN_ZERO;
        } else {
          assert(stack_idx < LENGTHOF(stack));
          *bytecode++ = LOOP_START;
          stack[stack_idx++] = bytecode;
          bytecode += sizeof(BfAddrInt);
        }
        break;
      case ']':
        assert(stack_idx > 0);
        if (stack_idx == 0) {
          return LOOP_START_ERROR;
        }
        *((BfAddrInt *) stack[--stack_idx]) = (BfAddrInt) ADDR_DIFF(bytecode, base);
        *bytecode++ = LOOP_END;
        *((BfAddrInt *) bytecode) = (BfAddrInt) (stack[stack_idx] - base - 1);
        bytecode += sizeof(BfAddrInt);
        break;
    }
  }
  *bytecode++ = HALT;
  *bytecode_size = (size_t) ADDR_DIFF(bytecode, base);

  return stack_idx == 0 ? BF_NO_ERROR : LOOP_START_ERROR;
}


/*!
 * @brief JIT-compile brainfuck source code
 * @param [out] bin       Machine code buffer
 * @param [out] bin_size  Size of JIT-compiled brainfuck code
 * @param [in]  code      Brainfuck source code
 * @return Status-code
 */
static int
jit_compile(unsigned char *bin, size_t *bin_size, const char *code)
{
  static unsigned char *stack[JUMP_STACK_SIZE];
  size_t stack_idx = 0;
  unsigned char *const base = bin;
  unsigned char *_bin;
  unsigned int  addr_diff;
  char ch;
  BfInt cnt;

#if defined(IS_X86)
  *bin++ = 0x55;  /* push ebp */
  *bin++ = 0x56;  /* push esi */
  *bin++ = 0x57;  /* push edi */
  *bin++ = 0x8b; *bin++ = 0x74; *bin++ = 0x24; *bin++ = 0x10;  /* mov putchar esp + 12 + 4 */
  *bin++ = 0x8b; *bin++ = 0x7c; *bin++ = 0x24; *bin++ = 0x14;  /* mov getchar esp + 12 + 8 */
  *bin++ = 0x8b; *bin++ = 0x6c; *bin++ = 0x24; *bin++ = 0x18;  /* mov stack   esp + 12 + 12 */
#elif defined(IS_X64_WIN)
  *bin++ = 0x56;  /* push rsi */
  *bin++ = 0x57;  /* push rdi */
  *bin++ = 0x55;  /* push rdp */
  *bin++ = 0x48; *bin++ = 0x89; *bin++ = 0xce;  /* mov putchar rcx */
  *bin++ = 0x48; *bin++ = 0x89; *bin++ = 0xd7;  /* mov getchar rdx */
  *bin++ = 0x4c; *bin++ = 0x89; *bin++ = 0xc5;  /* mov stack   r8 */
#else
  *bin++ = 0x53;                 /* push rbx */
  *bin++ = 0x55;                 /* push rbp */
  *bin++ = 0x41; *bin++ = 0x54;  /* push r12 */
  *bin++ = 0x48; *bin++ = 0x89; *bin++ = 0xfb;  /* mov putchar rdi */
  *bin++ = 0x48; *bin++ = 0x89; *bin++ = 0xf5;  /* mov getchar rsi */
  *bin++ = 0x49; *bin++ = 0x89; *bin++ = 0xd4;  /* mov stack   rdx */
#endif  /* IS_X86 */
  for (ch = *code; ch != '\0'; ch = *++code) {
    switch (ch) {
      case '>':
        cnt = count_char(code, ch);
        code += cnt - 1;
        /* add stack [cnt * 4] */
        if (cnt * 4 < 128) {
#if defined(IS_X86)
          *bin++ = 0x83; *bin++ = 0xc5;
          *bin++ = (bf_uint8_t) (cnt * 4);
#elif defined(IS_X64_WIN)
          *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xc5;
          *bin++ = (bf_uint8_t) (cnt * 4);
#else
          *bin++ = 0x49; *bin++ = 0x83; *bin++ = 0xc4;
          *bin++ = (bf_uint8_t) (cnt * 4);
#endif  /* defined(IS_X86) */
        } else {
#if defined(IS_X86)
          *bin++ = 0x81; *bin++ = 0xc5;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#elif defined(IS_X64_WIN)
          *bin++ = 0x48; *bin++ = 0x81; *bin++ = 0xc5;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#else
          *bin++ = 0x49; *bin++ = 0x81; *bin++ = 0xc4;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#endif  /* defined(IS_X86) */
        }
        break;
      case '<':
        cnt = count_char(code, ch);
        code += cnt - 1;
        /* sub stack [cnt * 4] */
        if (cnt * 4 < 128) {
#if defined(IS_X86)
          *bin++ = 0x83; *bin++ = 0xed;
          *bin++ = (bf_uint8_t) (cnt * 4);
#elif defined(IS_X64_WIN)
          *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xed;
          *bin++ = (bf_uint8_t) (cnt * 4);
#else
          *bin++ = 0x49; *bin++ = 0x83; *bin++ = 0xec;
          *bin++ = (bf_uint8_t) (cnt * 4);
#endif  /* defined(IS_X86) */
        } else {
#if defined(IS_X86)
          *bin++ = 0x81; *bin++ = 0xed;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#elif defined(IS_X64_WIN)
          *bin++ = 0x48; *bin++ = 0x81; *bin++ = 0xed;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#else
          *bin++ = 0x49; *bin++ = 0x81; *bin++ = 0xec;
          *((bf_int32_t *) bin) = (bf_int32_t) (cnt * 4); bin += sizeof(bf_int32_t);
#endif  /* defined(IS_X86) */
        }
        break;
      case '+':
        cnt = count_char(code, ch);
        code += cnt - 1;
        if (cnt == 1) {
          /* inc cur */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0xff; *bin++ = 0x45; *bin++ = 0x00;
#else
          *bin++ = 0x41; *bin++ = 0xff; *bin++ = 0x04; *bin++ = 0x24;
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        } else if (cnt < 128) {
          /* add cur cnt */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0x83; *bin++ = 0x45; *bin++ = 0x00;
          *bin++ = (bf_uint8_t) cnt;
#else
          *bin++ = 0x41; *bin++ = 0x83; *bin++ = 0x04; *bin++ = 0x24;
          *bin++ = (bf_uint8_t) cnt;
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        } else {
          /* add cur cnt */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0x81; *bin++ = 0x45; *bin++ = 0x00;
          *((bf_int32_t *) bin) = (bf_int32_t) cnt; bin += sizeof(bf_int32_t);
#else
          *bin++ = 0x41; *bin++ = 0x81; *bin++ = 0x04; *bin++ = 0x24;
          *((bf_int32_t *) bin) = (bf_int32_t) cnt; bin += sizeof(bf_int32_t);
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        }
        break;
      case '-':
        cnt = count_char(code, ch);
        code += cnt - 1;
        if (cnt == 1) {
          /* dec cur */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0xff; *bin++ = 0x4d; *bin++ = 0x00;
#else
          *bin++ = 0x41; *bin++ = 0xff; *bin++ = 0x0c; *bin++ = 0x24;
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        } else if (cnt < 128) {
          /* sub cur cnt */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0x83; *bin++ = 0x6d; *bin++ = 0x00;
          *bin++ = (bf_uint8_t) cnt;
#else
          *bin++ = 0x41; *bin++ = 0x83; *bin++ = 0x2c;
          *bin++ = 0x24; *bin++ = (bf_uint8_t) cnt;
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        } else {
          /* sub cur cnt */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0x81; *bin++ = 0x6d; *bin++ = 0x00;
          *((bf_int32_t *) bin) = (bf_int32_t) cnt; bin += sizeof(bf_int32_t);
#else
          *bin++ = 0x41; *bin++ = 0x81; *bin++ = 0x2c; *bin++ = 0x24;
          *((bf_int32_t *) bin) = (bf_int32_t) cnt; bin += sizeof(bf_int32_t);
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        }
        break;
      case '.':
#if defined(IS_X86)
        *bin++ = 0xff; *bin++ = 0x75; *bin++ = 0x00;  /* push cur */
        *bin++ = 0xff; *bin++ = 0xd6;                 /* call putchar */
        *bin++ = 0x58;                                /* pop eax */
#elif defined(IS_X64_WIN)
        *bin++ = 0x48; *bin++ = 0x8b; *bin++ = 0x4d; *bin++ = 0x00;  /* mov rcx cur */
        *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xec; *bin++ = 0x20;  /* sub rsp 32 */
        *bin++ = 0xff; *bin++ = 0xd6;                                /* call putchar */
        *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xc4; *bin++ = 0x20;  /* add rsp 32 */
#else
        *bin++ = 0x49; *bin++ = 0x8b; *bin++ = 0x3c; *bin++ = 0x24;  /* mov rdi cur */
        *bin++ = 0xff; *bin++ = 0xd3;                                /* call putchar */
#endif  /* defined(IS_X86) */
        break;
      case ',':
#if defined(IS_X86)
        *bin++ = 0xff; *bin++ = 0xd7;                 /* call getchar */
        *bin++ = 0x89; *bin++ = 0x45; *bin++ = 0x00;  /* mov cur eax */
#elif defined(IS_X64_WIN)
        *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xec; *bin++ = 0x20;  /* sub rsp 32 */
        *bin++ = 0xff; *bin++ = 0xd7;                                /* call putchar */
        *bin++ = 0x48; *bin++ = 0x83; *bin++ = 0xc4; *bin++ = 0x20;  /* add rsp 32 */
        *bin++ = 0x48; *bin++ = 0x89; *bin++ = 0x45; *bin++ = 0x00;  /* mov cur rax */
#else
        *bin++ = 0xff; *bin++ = 0xd5;                                /* call getchar */
        *bin++ = 0x41; *bin++ = 0x89; *bin++ = 0x04; *bin++ = 0x24;  /* mov cur eax */
#endif  /* defined(IS_X86) */
        break;
      case '[':
        if (code[1] == '-' && code[2] == ']') {
          code += 2;
          /* mov cur 0 */
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0xc7; *bin++ = 0x45; *bin++ = 0;
          *((bf_int32_t *) bin) = 0x00000000; bin += 4;
#else
          *bin++ = 0x41; *bin++ = 0xc7; *bin++ = 0x04; *bin++ = 0x24;
          *((bf_int32_t *) bin) = 0x00000000; bin += sizeof(bf_int32_t);
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
        } else {
          assert(stack_idx < LENGTHOF(stack));
          stack[stack_idx++] = bin;
#if defined(IS_X86) || defined(IS_X64_WIN)
          *bin++ = 0x8b; *bin++ = 0x45; *bin++ = 0x00;  /* mov eax cur */
#else
          *bin++ = 0x41; *bin++ = 0x8b; *bin++ = 0x04; *bin++ = 0x24;  /* mov eax cur */
#endif  /* defined(IS_X86) || defined(IS_X64_WIN) */
          *bin++ = 0x85; *bin++ = 0xc0;                 /* test eax eax */
          *bin++ = 0x0f; *bin++ = 0x84; *((bf_int32_t *) bin) = 0x00000000;  /* mov 0 (temporary) */
          bin += sizeof(bf_int32_t);
        }
        break;
      case ']':
        _bin = stack[--stack_idx];
        addr_diff = (unsigned int) ADDR_DIFF(bin, _bin);
        if (addr_diff < 128) {
          *bin++ = 0xeb;
          *bin++ = (bf_uint8_t) (-(addr_diff + 1) - sizeof(bf_uint8_t));
          *(_bin + JMP_OFFSET) = (unsigned char) ADDR_DIFF(bin, _bin + JMP_OFFSET + sizeof(bf_int32_t));
        } else {
          *bin++ = 0xe9;
          *((bf_int32_t *) bin) = (bf_int32_t) (-(addr_diff + 1) - sizeof(bf_int32_t));
          bin += sizeof(bf_int32_t);
          *((bf_int32_t *) (_bin + JMP_OFFSET)) = (bf_int32_t) ADDR_DIFF(bin, _bin + JMP_OFFSET + sizeof(bf_int32_t));
        }
        break;
    }
  }
#if defined(IS_X86)
  *bin++ = 0x5f;  /* pop edi */
  *bin++ = 0x5e;  /* pop esi */
  *bin++ = 0x5d;  /* pop ebp */
#elif defined(IS_X64_WIN)
  *bin++ = 0x5d;  /* pop rdp */
  *bin++ = 0x5f;  /* pop rdi */
  *bin++ = 0x5e;  /* pop rsi */
#else
  *bin++ = 0x41; *bin++ = 0x5c;  /* pop r12 */
  *bin++ = 0x5d;                 /* pop rbp */
  *bin++ = 0x5b;                 /* pop rbx */
#endif  /* defined(IS_X86) */
  *bin++ = 0xc3;  /* ret */

  *bin_size = (size_t) ADDR_DIFF(bin, base);
  return stack_idx == 0 ? BF_NO_ERROR : LOOP_START_ERROR;
}


/*!
 * @brief Translate brainfuck to C
 * @param [in] code  Pointer to the brainfuck source code
 * @return  Status-code
 */
static int
translate(FILE *fp, const char *code)
{
  char ch = *code;
  BfInt cnt;
  int depth = 1;

  print_code_header(fp);
  for (ch = *code; ch != '\0'; ch = *++code) {
    switch (ch) {
      case '>':
        cnt = count_char(code, '>');
        code += cnt - 1;
        print_indent(fp, depth);
        if (cnt == 1) {
          fputs("ptr++;\n", fp);
        } else {
          fprintf(fp, "ptr += %d;\n", cnt);
        }
        break;
      case '<':
        cnt = count_char(code, '<');
        code += cnt - 1;
        print_indent(fp, depth);
        if (cnt == 1) {
          fputs("ptr--;\n", fp);
        } else {
          fprintf(fp, "ptr -= %d;\n", cnt);
        }
        break;
      case '+':
        cnt = count_char(code, '+');
        code += cnt - 1;
        print_indent(fp, depth);
        if (cnt == 1) {
          fputs("(*ptr)++;\n", fp);
        } else {
          fprintf(fp, "*ptr += %d;\n", cnt);
        }
        break;
      case '-':
        cnt = count_char(code, '-');
        code += cnt - 1;
        print_indent(fp, depth);
        if (cnt == 1) {
          fputs("(*ptr)--;\n", fp);
        } else {
          fprintf(fp, "*ptr -= %d;\n", cnt);
        }
        break;
      case '.':
        print_indent(fp, depth);
        fputs("putchar(*ptr);\n", fp);
        break;
      case ',':
        print_indent(fp, depth);
        fputs("*ptr = getchar();\n", fp);
        break;
      case '[':
        print_indent(fp, depth);
        if (code[1] == '-' && code[2] == ']') {
          code += 2;
          fputs("*ptr = 0;\n", fp);
        } else {
          fputs("while (*ptr) {\n", fp);
          depth++;
        }
        break;
      case ']':
        depth--;
        print_indent(fp, depth);
        fputs("}\n", fp);
        break;
    }
  }
  print_code_footer(fp);
  return BF_NO_ERROR;
}


/*!
 * @brief Find the end of loop
 * @param [in] code  Pointer to the brainfuck source code
 * @return  Pointer to the end of loop of brainfuck source code
 */
static const char *
find_loop_end(const char *code)
{
  int depth = 1;
  char ch;
  while (ch = *++code, depth > 0) {
    switch (ch) {
      case '[':  depth++; break;
      case ']':  depth--; break;
      case '\0': return NULL;
    }
  }
  return code - 1;
}


/*!
 * @brief Find the start of loop
 * @param [in] code  Pointer to the brainfuck source code
 * @return  Pointer to the start of loop of brainfuck source code
 */
static const char *
find_loop_start(const char *code)
{
  int depth = 1;
  char ch;
  while (ch = *--code, depth > 0) {
    switch (ch) {
      case '[': depth--; break;
      case ']': depth++; break;
    }
  }
  return code;
}


/*!
 * @brief Count how many given character are continuous.
 * @return The number of consecutive characters
 */
static BfInt
count_char(const char *code, char ch)
{
  BfInt cnt = 1;
  while (*++code == ch) {
    cnt++;
  }
  return cnt;
}


/*!
 * @brief Print the indent of translated C-source code
 */
static void
print_indent(FILE *fp, int depth)
{
  int i;
  for (i = 0; i < depth; i++) {
    fprintf(fp, "%s", INDENT_STR);
  }
}


/*!
 * @brief Print the header of translated C-source code
 * @param [in,out] fp  Output file pointer
 */
static void
print_code_header(FILE *fp)
{
  fprintf(fp,
      "#include <stdio.h>\n"
      "#include <stdlib.h>\n\n"
      "#define MEMORY_SIZE %d\n\n"
      "int main(void)\n"
      "{\n"
      INDENT_STR "static char memory[MEMORY_SIZE] = {0};\n"
      INDENT_STR "char *ptr = memory;\n\n", MEMORY_SIZE);
}


/*!
 * @brief Print the footer of translated C-source code
 * @param [in,out] fp  Output file pointer
 */
static void
print_code_footer(FILE *fp)
{
  fputs(
      "\n"
      INDENT_STR "return EXIT_SUCCESS;\n"
      "}\n", fp);
}


/*!
 * @brief Show the byte code in hexadecimal
 * @param [in] bytecode  Brainfuck byte code
 * @param [in] size      size of brainfuck byte code
 */
static void
show_bytecode(const unsigned char *bytecode, size_t bytecode_size)
{
  size_t i, j;
  size_t quot = bytecode_size / 16;
  size_t rem  = bytecode_size % 16;
  int addr_cnt = 0;
  for (i = 0; i < quot; i++) {
    printf("0x%04x:", addr_cnt);
    addr_cnt += 16;
    for (j = 0; j < 16; j++) {
      printf(" %02x", *bytecode++);
    }
    puts("");
  }
  printf("0x%04x:", addr_cnt);
  for (i = 0; i < rem; i++) {
    printf(" %02x", *bytecode++);
  }
  puts("");
}


/*!
 * @brief Show the byte code in mnemonic format.
 * @param [in] fp        Output file pointer
 * @param [in] bytecode  Brainfuck byte code
 */
static void
show_mnemonic(FILE *fp, const unsigned char *bytecode)
{
  const unsigned char *const base = bytecode;
  for (; *bytecode; bytecode++) {
    fprintf(fp, "%04d: ", (int) ADDR_DIFF(bytecode, base));
    switch (*bytecode) {
      case PTR_ADD:
        bytecode++;
        fprintf(fp, "PTR_ADD %d\n", *((const BfSeekInt *) bytecode));
        bytecode += sizeof(BfSeekInt) - 1;
        break;
      case PTR_SUB:
        bytecode++;
        fprintf(fp, "PTR_SUB %d\n", *((const BfSeekInt *) bytecode));
        bytecode += sizeof(BfSeekInt) - 1;
        break;
      case ADD:
        bytecode++;
        fprintf(fp, "ADD %d\n", *((const BfInt *) bytecode));
        bytecode += sizeof(BfInt) - 1;
        break;
      case SUB:
        bytecode++;
        fprintf(fp, "SUB %d\n", *((const BfInt *) bytecode));
        bytecode += sizeof(BfInt) - 1;
        break;
      case PUT_CHAR:
        fputs("PUT\n", fp);
        break;
      case READ_CHAR:
        fputs("READ\n", fp);
        break;
      case LOOP_START:
        bytecode++;
        fprintf(fp, "BEZ %d\n", (*((const BfAddrInt *) bytecode) + (BfAddrInt) sizeof(BfAddrInt) + 1));
        bytecode += sizeof(BfAddrInt) - 1;
        break;
      case LOOP_END:
        bytecode++;
        fprintf(fp, "GOTO %d\n", *((const BfAddrInt *) bytecode));
        bytecode += sizeof(BfAddrInt) - 1;
        break;
      case ASSIGN_ZERO:
        fputs("ASSIGN_ZERO\n", fp);
        break;
    }
  }
}
