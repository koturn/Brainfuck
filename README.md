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

Options                            | Function
-----------------------------------|---------------------------------------------------------------
```-b```, ```--bytecode```         | Show code in hexadecimal
```-e```                           | Execute one line code
```-h```, ```--help```             | Show help and exit
```-m```, ```--mnemonic```         | Show byte code in mnemonic format
```-n```, ```--normal```           | Execute in normal mode (Without optimization before execution)
```-o FILE```, ```--output=FILE``` | Specify output filename
```-t```, ```--translate```        | Translate brainfuck to C source code


## Build

Use [Makefile](Makefile). 

```
$ make
```

This program uses getopt, so you can compile with gcc only.



## References

- [http://compsoc.dur.ac.uk/whitespace/](http://compsoc.dur.ac.uk/whitespace/)


## LICENSE

This software is released under the MIT License, see [LICENSE](LICENSE).
