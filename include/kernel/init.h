/** @file */
#ifndef INIT_H
#define INIT_H

#include <stdint.h>

/// This type defines an initcall function, which is a function automatically
/// called when the kernel is started. Ue `init_register()` to register such a
/// function.
typedef int (*initcall_t)(void);

extern unsigned char __initcall_start;
extern unsigned char __initcall_end;

// TODO: We should ideally declare these declarations `static`, however LLVM
// strips them out because they are unused and despite `unused` being set.
#define __initcall(func)                                                       \
  initcall_t __initcall_##func                                                 \
    __attribute__((unused, __section__(".initcall_functions"))) = func

/**
 * Registers an initcall function that will be loaded after the
 * architecture-specific code initialization.
 */
#define init_register(func) __initcall(func)

#endif
