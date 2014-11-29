Brainfuck
=========

Brainfuck interpreter and C-translator.


## Usage

### Run Brainfuck program

```sh
$ ./brainfuck [Brainfuck source file]
```

### Tanslate Brainfuck to C

Specify ```-t``` flag and ```-o``` flag.

```sh
$ ./brainfuck [Brainfuck source file] -t -o out.c
```

If you don't specify output file with ```-o```, C source code will output
stdout.

### Options

Options                                 | Function
----------------------------------------|---------------------------------------------------------------
```-b```, ```--bytecode```              | Show code in hexadecimal
```-e [CODE]```, ```--execute=[CODE]``` | Execute one line code
```-h```, ```--help```                  | Show help and exit
```-m```, ```--mnemonic```              | Show byte code in mnemonic format
```-n```, ```--normal```                | Execute in normal mode (Without optimization before execution)
```-o FILE```, ```--output=FILE```      | Specify output filename
```-t```, ```--translate```             | Translate brainfuck to C source code


## Build

Use [Makefile](Makefile).

```sh
$ make
```

If you want to build with MSVC, use [msvc.mk](msvc.mk).
[msvc.mk](msvc.mk) is written for nmake.

```sh
> nmake /f msvc.mk
```


## Dependent libraries

#### MSVC only

- [getopt clone](https://github.com/koturn/getopt)


## References

- [http://en.wikipedia.org/wiki/Brainfuck](http://en.wikipedia.org/wiki/Brainfuck)


## LICENSE

This software is released under the MIT License, see [LICENSE](LICENSE).
