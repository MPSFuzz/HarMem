#define _GNU_SOURCE
#include "trace_fn_instrument.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FUNCS 8192

struct fn_entry {
  void *addr;
  char name[256];
  uint64_t hit_count;
};

static struct fn_entry g_table[MAX_FUNCS];
static int g_inited = 0;

// Thread-local flag to prevent re-entrancy
static __thread int g_in_trace = 0;
static void NO_INSTRUMENT trace_fn_auto_dump(void) __attribute__((destructor));

static NO_INSTRUMENT int find_or_add(void *addr, const char *name) {
  unsigned long h = ((unsigned long)addr >> 4) % MAX_FUNCS; // Simple hash
  for (int i = 0; i < MAX_FUNCS; i++) {
    int idx = (h + i) % MAX_FUNCS;
    if (g_table[idx].addr == NULL) {
      g_table[idx].addr = addr;
      strncpy(g_table[idx].name, name ? name : "?",
              sizeof(g_table[idx].name) - 1);
      g_table[idx].name[sizeof(g_table[idx].name) - 1] =
          '\0'; // Ensure null-termination
      g_table[idx].hit_count = 0;
      return idx;
    }
    if (g_table[idx].addr == addr) {
      return idx;
    }
  }

  return -1; // Table is full
}

void NO_INSTRUMENT trace_fn_init(void) {
  if (g_inited)
    return;
  memset(g_table, 0, sizeof(g_table));
  g_inited = 1;
}

void NO_INSTRUMENT trace_fn_shutdown(void) {
  // Nothing to do for now
}

void NO_INSTRUMENT __cyg_profile_func_enter(void *this_fn, void *call_site) {
  (void)call_site;
  if (g_in_trace)
    return;
  g_in_trace = 1;

  if (!g_inited)
    trace_fn_init();

  Dl_info info;
  if (dladdr(this_fn, &info) != 0 && info.dli_sname) {
    int idx = find_or_add(this_fn, info.dli_sname);
    if (idx >= 0)
      g_table[idx].hit_count++;
  }

  g_in_trace = 0;
}

void NO_INSTRUMENT __cyg_profile_func_exit(void *this_fn, void *call_site) {
  (void)this_fn;
  (void)call_site;
  // Do nothing on function exit in this prototype
}

void NO_INSTRUMENT trace_fn_dump(const char *path) {
  if (!path)
    return;
  FILE *fp = fopen(path, "w");
  if (!fp)
    return;

  fprintf(fp, "{\n");
  fprintf(fp, " \"functions\": [\n");
  int first = 1;
  for (int i = 0; i < MAX_FUNCS; i++) {
    if (g_table[i].addr == NULL || g_table[i].hit_count == 0)
      continue;
    if (!first)
      fprintf(fp, ",\n");
    first = 0;
    fprintf(fp, " {\"name\": \"%s\", \"hit_count\": %llu }", g_table[i].name,
            (unsigned long long)g_table[i].hit_count);
  }
  if (!first)
    fprintf(fp, "\n");
  fprintf(fp, " ]\n");
  fprintf(fp, "} \n");

  fclose(fp);
}

static NO_INSTRUMENT void trace_fn_auto_dump(void) {
  const char *trace_out = getenv("TRACE_FN_OUTPUT");
  if (trace_out && trace_out[0] != '\0') {
    trace_fn_dump(trace_out);
  }
}