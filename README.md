# pwndra

A collection of pwn/CTF related utilities for Ghidra

## Utilities

* [Replace Constants](#replace-constants)
* [Annotate Syscalls](#annotate-syscalls)
* [Character Conversion](#character-conversion)
* [Goto Main](#goto-main)

### Replace Constants

This utility will attempt to replace known constants in functions with their
human readable counterpart.

![pwndra constants](https://github.com/0xb0bb/pwndra/blob/master/docs/images/pwndra_constants.png?raw=true)

### Annotate Syscalls

This utility will attempt to find and identify system calls (and arguments).

*Annotation in the decompiler view*
![pwndra syscalls](https://github.com/0xb0bb/pwndra/blob/master/docs/images/pwndra_syscalls.png?raw=true)

*Arguments are annotated in the disassembler view*
![pwndra syscalls](https://github.com/0xb0bb/pwndra/blob/master/docs/images/pwndra_syscalls_disas.png?raw=true)

### Character Conversion

The correct workflow to convert displayed data in an operand is to right click
the value and select the conversion type under the `Convert` submenu, however,
on request I have made a script to convert the display type of operands to
`char` so it can be used with a keyboard shortcut for convenience (IDA style).

To use it select the `In Tool` option of the `UtilitiesConvertCharacter.py` script and
then select a numeric operand and hit `shift+r` to convert to a string. You
can change the shortcut by editing the line that contains the comment with
`keybinding` in it at the top of the script.

### Goto Main

One annoying difference between Ghidra and IDA is that Ghidra makes no
attempt to jump to `main()` (or the entry point) when you load a binary.
The `UtilitiesGotoMain.py` script aims to correct that. Run it directly
or if integrated with `In Tool` then hit `ctrl`+`m` and it will attempt
to dynamically find `main()` and move focus to that function.

If there is no `main()` function detected, it will jump to the entry
function. If you run on a stripped binary then it will rename the `main`
function for you.

---

## Installation

Clone the repository or download and extract somewhere. In Ghidra, open
the `Script Manager` (`Window` -> `Script Manager`) click the `Script 
Directory` button and add `pwndra/scripts` to the list.

Once the script directory is added to Ghidra you can find the scripts in
the `Pwn` category. You can run the scripts directly from the `Script 
Manager` if you like but the scripts also have menus and keyboard shortcuts
for ease of use. In order to activate the menus and shortcuts you must
click the `In Tool` checkbox next to the scripts you wish to integrate
into the tool.

If you clicked `In Tool` the menus will be under `Analysis` -> `Pwn` and
any shortcuts for scripts are listed in the menu item that uses that
shortcut.

## Usage

There are several frontends available:

* aarch64
* amd64
* arm (oabi/eabi)
* hppa
* i386
* m68k
* mips (n32/o32/n64)
* powerpc
* powerpc64
* sh
* sh4
* sparc
* sparc64
* thumb

You can either run one of those frontend scripts directly (through the
`Script Manager` or if you clicked `In Tool` you can access a menu;
`Analysis` -> `Pwn` -> `Tool Name`).

There is an `Auto` frontend that will automatically detect the current loaded
program for you. This can also be accessed with the keyboard shortcut which
is specified in the menu item for the tool.

The scripts have two modes of operation, the default is to operate globally,
the second is to only operate on a given selection. This is useful for those
times where you have two binary modes interlaced in the same code such as
`i386`/`amd64` or `thumb`/`arm`.
