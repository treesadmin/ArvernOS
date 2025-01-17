<!-- doxygen: \mainpage Introduction -->

# ArvernOS

[![Gitter](https://badges.gitter.im/willdurand-kernel/community.svg)](https://gitter.im/willdurand-kernel/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) [![CircleCI](https://circleci.com/gh/willdurand/ArvernOS/tree/master.svg?style=svg)](https://circleci.com/gh/willdurand/ArvernOS/tree/master)

ArvernOS (formerly known as "willOS") is a minimal and experimental monolithic
kernel (not really an Operating System because it cannot do a lot of things
currently). Some screencasts are available in [this Twitter
thread][twitter-thread].

## Goals

The main goal of this project is to learn about operating systems, kernel
development, different architectures and improve my C skills. ArvernOS is a
monolithic (and hopefully modular) [kernel](./src/kernel/README.md) with a
unified homemade [libc/libk](./src/libc/README.md), and
[userland](./src/userland/README.md) programs.

The roadmap isn't clearly defined yet and it mainly depends on what I'd like to
work on when I have time to spend on this project.

## Architectures, boards and tiers

ArvernOS supports the architectures and boards listed below. Support for
different architectures and boards are organized into two tiers, each with a
different set of guarantees.

### Tier 1

Tier 1 is the reference implementation and very likely the most advanced.

Current Tier 1 archs/boards:

- **x86_64**
  - generic

### Tier 2

Tier 2 is guaranteed to build but not all features have been implemented yet.
Features are defined by the reference implementation and once feature parity is
achieved, an architecture and/or board should move to Tier 1. Boards for which
we cannot run enough tests in CI (e.g., because QEMU does not support the board)
should stay in Tier 2, though.

Current Tier 2 archs/boards:

- **aarch32**
  - [Raspberry Pi 2](./src/kernel/arch/aarch32/board/raspi2/README.md)
- **aarch64**
  - [Raspberry Pi 3](./src/kernel/arch/aarch64/board/raspi3/README.md)

## Hacking on ArvernOS

This section (and its sub-sections) are written for everyone interested in
building and working on ArvernOS.

### Setting up a development environment

The following dependencies are required to build this project:

- `llvm` (version 13 currently)
- `make`
- `qemu` (version >= 5)

If you want to work on the `x86_64` architecture, you'll need the following
extra dependencies:

- `nasm`
- `grub-mkrescue`
- `xorriso`

If you want to work on ARM architectures (`aarch32` or `aarch64`), you'll need
the following extra dependencies:

- `gcc-arm-none-eabi`
- `u-boot-tools`

Note: The recommended way to work on this project is to use Docker.

#### Getting the sources

This project contains [git submodules][git-submodules]. You have to clone the
main project as well as the submodules, either by using this command:

```
$ git clone --recurse-submodules <url pointing to this repo>
```

or by using this command if you already have a copy of this git repository:

```
$ git submodule update --init
```

#### Docker (recommended way)

Use [Docker](https://docs.docker.com/) with the provided
[`Dockerfile`][dockerfile]. You can either use the
[`willdurand/arvernos-toolchain` image from DockerHub][dockerhub-toolchain] or
build your own:

```
$ docker build -t willdurand/arvernos-toolchain .
[...]
```

You can then use it with `docker run`:

```
$ docker run -it --rm -v $(pwd):/app willdurand/arvernos-toolchain make help
ArvernOS - available commands for arch=x86_64

clean                          remove build artifacts
debug                          build the project in debug mode
docs                           build the docs
fmt                            automatically format the code with clang-format
gdb                            build, run the project in debug mode and enable GDB
help                           show this help message
libc                           build the libc
release                        build the project in release mode
run-debug                      run the project in debug mode
run-release                    run the project in release mode
run-test                       run the project in test mode
test                           run the unit tests
userland                       compile the userland programs (statically linked to libc)
version                        print tool versions
```

Note: The output of the `make help` command may contain different commands
depending on the architecture and board configured.

#### MacOS

Install [Homebrew](https://brew.sh/), then run the following commands:

```
$ brew install nasm xorriso qemu llvm u-boot-tools
```

#### Linux

The `tools/install-linux-deps` script is used to install the dependencies. It is
currently used by both the `Dockerfile` and Circle CI.

### Building ArvernOS

You first need to install the development dependencies in order to build
ArvernOS. The different final files are located in the `build/<arch>/dist/` or
`build/<arch>/<board>/dist/` folder.

#### Debug mode

To build the image in debug mode, run:

```
$ make clean ; make debug
```

To compile the OS in debug mode, build the image, and start `qemu` with the OS
loaded, run:

```
$ make clean ; make run-debug
```

Note: Some boards aren't supported in QEMU.

##### QEMU monitor

When running `make run-debug`, the [QEMU monitor][] can be accessed over TCP on
port `5555`. You can use tools like `telnet` or `nc`:

```
$ telnet 127.0.0.1 5555
```

##### Logging

In debug mode, logging very likely uses the serial port `COM1` to write various
debugging information. QEMU is configured to write the output of this serial
port to a logfile in `./log/`. `DEBUG` level logs are not necessarily written by
default, though, and it is possible to enable `DEBUG` logs for specific modules
like this:

```
# Enable the debug logs for the "net" and "fs" modules
$ make clean ; make run-debug ENABLE_NET_DEBUG=1 ENABLE_FS_DEBUG=1
```

The available debug variables are:

- `ENABLE_CONFIG_DEBUG`
- `ENABLE_CORE_DEBUG`
- `ENABLE_FS_DEBUG`
- `ENABLE_MMU_DEBUG`
- `ENABLE_NET_DEBUG`
- `ENABLE_PROC_DEBUG`
- `ENABLE_SYS_DEBUG`
- `ENABLE_USERLAND_DEBUG`

##### Stack traces

Log files may contain stack traces without debug symbols if the symbols haven't
been loaded:

```
[...]
DEBUG    | src/kernel/arch/x86_64/kshell/kshell.c:108:run_command(): command='selftest' argc=1
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:30:kernel_dump_stacktrace(): kernel stacktrace:
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace(): 00000000001163B3 - ???+0x0
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace(): 0000000000115941 - ???+0x0
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace(): 0000000000115BE1 - ???+0x0
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace(): 00000000001152BF - ???+0x0
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace(): 000000000010935B - ???+0x0
```

Use the `tools/fix-stacktrace.py` script to add missing symbol names to the
output:

```
$ ./tools/fix-stacktrace.py build/x86_64/dist/symbols.txt log/x86_64-debug.log
[...]
DEBUG    | src/kernel/arch/x86_64/kshell/kshell.c:108:run_command(): command='selftest' argc=1
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:30:kernel_dump_stacktrace(): kernel stacktrace:
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace():   00000000001163B3 - selftest+0x63
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace():   0000000000115941 - run_command+0x271
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace():   0000000000115BE1 - kshell_run+0x181
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace():   00000000001152BF - kmain+0x107f
DEBUG    | src/kernel/arch/x86_64/kernel/panic.c:39:kernel_dump_stacktrace():   000000000010935B - long_mode_start+0x13
```

In addition, you might want to find the corresponding line of code in the source
files by using `llvm-addr2line` or `llvm-symbolizer`:

```
$ llvm-symbolizer-13 --obj=build/x86_64/dist/kernel-x86_64.bin 0x01163B3
print_selftest_header
/path/to/ArvernOS/src/kernel/kshell/selftest.c:12:3
selftest
/path/to/ArvernOS/src/kernel/kshell/selftest.c:30:3
```

```
$ llvm-addr2line-13 -e build/x86_64/dist/kernel-x86_64.bin 01163B3
/path/to/ArvernOS/src/kernel/kshell/selftest.c:12
```

##### Debugging

Use `make gdb` to run the project in debug mode with QEMU configured to wait for
[gdb][] to connect. This has been tested with `vim` (`:Termdebug`) and VS Code.

A sensible configuration is automatically generated when this command is
executed (see also: `make gdbinit`). If a file named `.gdbinit.local` exists in
the project's root directory, its content will be appended to the generated
`.gdbinit` file.

Note: `make gdb` calls `make run-debug` under the hood so all configuration
options are also supported. For example, it is possible to run `make gdb KERNEL_CMDLINE="kshell selftest"`.

#### Release mode

To compile the OS in release mode, build the image, and start `qemu` with the OS
loaded, run:

```
$ make clean ; make run-release
```

#### config files

`config` files are used to configure how a build works. The content must be
compatible with `make`. Here is an example:

```
# LLVM config on MacOS with Homebrew
LLVM_PREFIX = /usr/local/opt/llvm@13/bin/
LLVM_SUFFIX =

# Always enable the Undefined Behavior sanitizer
UBSAN = 1

# Logging
ENABLE_CORE_DEBUG     = 1
ENABLE_PROC_DEBUG     = 1
ENABLE_SYS_DEBUG      = 1
ENABLE_USERLAND_DEBUG = 1
```

## License

ArvernOS is released under the MIT License. See the bundled
[LICENSE][license] file for
details. In addition, some parts of this project have their own licenses
attached (either in the source files or in a `LICENSE` file next to them).

[dockerfile]: https://github.com/willdurand/ArvernOS/blob/master/Dockerfile
[dockerhub-toolchain]: https://hub.docker.com/repository/docker/willdurand/arvernos-toolchain
[gdb]: https://www.sourceware.org/gdb/
[git-submodules]: https://git-scm.com/book/en/v2/Git-Tools-Submodules
[license]: https://github.com/willdurand/ArvernOS/blob/master/LICENSE.md
[twitter-thread]: https://twitter.com/couac/status/1201278626211254274
[qemu monitor]: https://www.qemu.org/docs/master/system/monitor.html
