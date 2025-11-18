/*
   aflgo compiler (NPM-ready)
   --------------------------

   This version is adapted for LLVM/Clang new pass manager plugin loading:
   it uses -fpass-plugin=<path>/aflgo-pass.so instead of -Xclang -load ...
   and adopts safer defaults for modern Clang (>=15/16).

   Licensed under the Apache License, Version 2.0
*/

#define AFL_MAIN

#include "../afl-2.57b/alloc-inl.h"
#include "../afl-2.57b/config.h"
#include "../afl-2.57b/debug.h"
#include "../afl-2.57b/types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static u8 *obj_path;       /* Path to runtime libraries         */
static u8 **cc_params;     /* Parameters passed to the real CC  */
static u32 cc_par_cnt = 1; /* Param count, including argv0      */

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8 *argv0) {

  u8 *afl_path = getenv("AFLGO");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/instrument/aflgo-runtime.o", afl_path);

    if (!access(tmp, R_OK)) {
      obj_path = alloc_printf("%s/instrument", afl_path);
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/aflgo-runtime.o", dir);

    if (!access(tmp, R_OK)) {
      obj_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);
  }

  FATAL("Unable to find 'aflgo-runtime.o' or 'aflgo-pass.so'.");
}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char **argv) {

  u8 fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  u8 *name;
  static u8 *opt_distance = 0, *opt_targets = 0, *opt_outdir = 0;
  // static int user_passes_set = 0;
  // static int user_O = -1;

  /* allocate a bit more space to be safe */
  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

  name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    name++;

  if (!strcmp(name, "afl-clang-fast++") || !strcmp(name, "aflgo-clang++")) {
    u8 *alt_cxx = getenv("AFL_CXX");
    cc_params[0] = alt_cxx ? alt_cxx : (u8 *)"clang++";
  } else {
    u8 *alt_cc = getenv("AFL_CC");
    cc_params[0] = alt_cc ? alt_cc : (u8 *)"clang";
  }

#ifdef USE_TRACE_PC
  cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
  cc_params[cc_par_cnt++] = "-mllvm";
  cc_params[cc_par_cnt++] = "-sanitizer-coverage-block-threshold=0";
#error AFLGO has not supported trace-pc-guard yet
#else
  /*
    For New Pass Manager (NPM) plugins use -fpass-plugin=<path>
    This is the recommended way to load plugins into clang's pipeline
    for recent LLVM/Clang versions (>=15/16). See LLVM docs.
    (If you still need legacy loading, consider adding -flegacy-pass-manager
     but for NPM plugins this is NOT desired.)
  */
  cc_params[cc_par_cnt++] =
      alloc_printf("-fpass-plugin=%s/aflgo-pass.so", obj_path);
#endif /* ^USE_TRACE_PC */

  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v"))
    maybe_linking = 0;

  while (--argc) {
    u8 *cur = *(++argv);

    /*
      NOTE:
      Historically aflgo inserted "-mllvm" before custom flags like -distance,
      -targets, -outdir so the clang cc1 stage would forward them to the
      plugin. For NPM plugins you may prefer another arg passing convention.
      Here we keep a conservative approach: we forward user args verbatim,
      and for backwards compatibility we *also* add -mllvm when encountering
      the known aflgo-specific flags (harmless on many clang versions).
      If you prefer strictly non -mllvm behavior, remove that extra insertion.
    */
    if (!strncmp(cur, "-distance=", 10)) {
      opt_distance = cur + 10;
      continue;
    }
    if (!strncmp(cur, "-targets=", 9)) {
      opt_targets = cur + 9;
      continue;
    }
    if (!strncmp(cur, "-outdir=", 8)) {
      opt_outdir = cur + 8;
      continue;
    }

    // if (!strcmp(cur, "-mllvm") && argc > 1 &&
    //     !strncmp(argv[1], "-passes=", 8)) {
    //   user_passes_set = 1;
    // }

    // if (!strcmp("cur", "-O0")) {
    //   user_O = 0;
    // }
    // if (!strcmp("cur", "-O1")) {
    //   user_O = 1;
    // }
    // if (!strcmp("cur", "-O2")) {
    //   user_O = 2;
    // }
    // if (!strcmp("cur", "-O3")) {
    //   user_O = 3;
    // }

    if (!strcmp(cur, "-m32"))
      bit_mode = 32;
    if (!strcmp(cur, "-m64"))
      bit_mode = 64;

    if (!strcmp(cur, "-x"))
      x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE"))
      fortify_set = 1;

    if (!strcmp(cur, "-shared"))
      maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
      continue;

    cc_params[cc_par_cnt++] = cur;
  }

  if (opt_distance)
    setenv("AFLGO_DISTANCE", (char *)opt_distance, 1);
  if (opt_targets)
    setenv("AFLGO_TARGETS", (char *)opt_targets, 1);
  if (opt_outdir)
    setenv("AFLGO_OUTDIR", (char *)opt_outdir, 1);

  // if (!user_passes_set) {
  //   const char *Otag = "O1";
  //   if (user_O == 0)
  //     Otag = "O0";
  //   else if (user_O == 2)
  //     Otag = "O2";
  //   else if (user_O == 3)
  //     Otag = "O3";

  //   cc_params[cc_par_cnt++] = "-mllvm";
  //   cc_params[cc_par_cnt++] =
  //       alloc_printf("-passes=default<%s>,module(aflgo-npm)", Otag);
  // }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";
  }

  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN"))
        FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";
    }
  }

#ifdef USE_TRACE_PC

  if (getenv("AFL_INST_RATIO"))
    FATAL("AFL_INST_RATIO not available at compile time with 'trace-pc'.");

#endif /* USE_TRACE_PC */

  /* Optimization / debug defaults:
     For reliable analysis and to avoid heavy IR transformations at compile
     time, we default to -O0 -g unless AFL_DONT_OPTIMIZE is set. This keeps
     debug info and function structure stable for the pass. Users can override
     with explicit -O flags when invoking aflgo-clang.
  */

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O0";
  }

  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
  }

  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* Persistent/deferred forkserver support macros (unchanged) */

  cc_params[cc_par_cnt++] =
      "-D__AFL_LOOP(_A)="
      "({ static volatile char *_B __attribute__((used)); "
      " _B = (char*)\"" PERSIST_SIG "\"; "
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif /* ^__APPLE__ */
      "_L(_A); })";

  cc_params[cc_par_cnt++] =
      "-D__AFL_INIT()="
      "do { static volatile char *_A __attribute__((used)); "
      " _A = (char*)\"" DEFER_SIG "\"; "
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif /* ^__APPLE__ */
      "_I(); } while (0)";

  if (maybe_linking) {

    if (x_set) {
      cc_params[cc_par_cnt++] = "-x";
      cc_params[cc_par_cnt++] = "none";
    }

    switch (bit_mode) {

    case 0:
      cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime.o", obj_path);
      break;

    case 32:
      cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime-32.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m32 is not supported by your compiler");

      break;

    case 64:
      cc_params[cc_par_cnt++] = alloc_printf("%s/aflgo-runtime-64.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m64 is not supported by your compiler");

      break;
    }
  }

  cc_params[cc_par_cnt] = NULL;
}

/* Main entry point */

int main(int argc, char **argv) {

  if (isatty(2) && !getenv("AFL_QUIET")) {

#ifdef USE_TRACE_PC
    SAYF(cCYA "aflgo-compiler (yeah!) [tpcg] " cBRI VERSION cRST "\n");
#else
    SAYF(cCYA "aflgo-compiler (yeah!) " cBRI VERSION cRST "\n");
#endif /* ^USE_TRACE_PC */
  }

  if (argc < 2) {

    SAYF(
        "\n"
        "This is a helper application for aflgo. It serves as a drop-in "
        "replacement\n"
        "for clang, letting you recompile third-party code with the required "
        "runtime\n"
        "instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=aflgo-clang ./configure\n"
        "  CXX=aflgo-clang++ ./configure\n\n"

        "In contrast to the traditional afl-clang tool, this version is "
        "implemented as\n"
        "an LLVM pass plugin and tends to offer improved performance with slow "
        "programs.\n\n"

        "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. "
        "Setting\n"
        "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n");

    exit(1);
  }

  find_obj(argv[0]);

  edit_params(argc, argv);

  FILE *f = fopen("/tmp/"
                  "aflgo_clang_params.txt",
                  "w");
  if (f) {
    for (u32 i = 0; i < cc_par_cnt; i++) {
      fprintf(f, "param[%u] = %s\n", i, cc_params[i]);
    }
    fclose(f);
  }

  execvp(cc_params[0], (char **)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;
}
