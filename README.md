# pwndra

A collection of pwn/CTF related utilities for Ghidra

## Utilities

### Replace Constants

This utility will attempt to replace known constants in functions with
their human readable counterpart.

![pwndra constants](https://github.com/0xb0bb/pwndra/blob/master/docs/images/pwndra_constants.png?raw=true)

#### Usage

There are several frontends available:

* aarch64
* amd64
* arm
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
`Analysis` -> `Pwn` -> `Constants`).

There is an `Auto` frontend that will atuomatically detect the current loaded
program for you. This can also be accessed with the keyboard shortcut: `ctrl`+`6`.

The scripts have two modes of operation, the default is a global replacement
of known constants, the second is to only operate on a given selection. This is
useful for those times where you have two binary modes interlaced in the same
code such as `i386`/`amd64` or `thumb`/`arm`.

## Installation

Add the files to an existing Ghidra script directory or add it as a new
script directory by clicking the `Script Directories` button within the
`Script Manager` window (`Window` -> `Script Manager`).

Some of the scripts have keyboard shortcuts or add menu items to Ghidra (visible
under `Analysis` -> `Pwn`) in order to integrate the scripts into Ghidra you must
click the `In Tool` checkbox next to the script on the `Script Manager` window.
