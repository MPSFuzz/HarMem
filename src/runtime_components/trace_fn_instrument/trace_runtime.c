#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NO_INSTRUMENT
#define NO_INSTRUMENT __attribute__((no_instrument_function))
#endif

typedef enum {
  TRACE_EVT_FUNC_ENTER = 0,
  TRACE_EVT_FUNC_EXIT = 1,
  TRACE_EVT_BRANCH = 2,
  TRACE_EVT_CALL = 3,
  TRACE_EVT_MARKER = 4,
} trace_event_kind_t;

typedef struct {
  trace_event_kind_t kind;
  uint32_t module_id;
  uint32_t func_id;
  uint32_t aux_id; // branch_id or call_id
  int32_t aux_val; // cond_true(1/0); call: to_func_id
} trace_event_t;

static __thread trace_event_t *g_events = NULL;
static __thread size_t g_event_count = 0;
static __thread size_t g_event_cap = 0;

void trace_fn_enter(uint32_t module_id, uint32_t func_id);
void trace_fn_exit(uint32_t module_id, uint32_t func_id);
void trace_branch(uint32_t module_id, uint32_t func_id, uint32_t branch_id,
                  int cond_true);
void trace_call_edge(uint32_t module_id, uint32_t from_func_id,
                     uint32_t to_func_id, uint32_t call_id);
void trace_marker(uint32_t module_id, uint32_t func_id, uint32_t marker_id);

static NO_INSTRUMENT void trace_runtime_flush(void) __attribute__((destructor));

static NO_INSTRUMENT void trace_record_event(trace_event_t ev) {
  if (g_event_count == g_event_cap) {
    size_t new_cap = g_event_cap ? g_event_cap * 2
                                 : 1024; // dynamic alloc a buffer for events
    trace_event_t *nb =
        (trace_event_t *)realloc(g_events, new_cap * sizeof(trace_event_t));

    if (!nb) {
      // allocation failed, drop the event
      return;
    }

    g_events = nb;
    g_event_cap = new_cap;
  }
  g_events[g_event_count++] = ev;
}

NO_INSTRUMENT void trace_fn_enter(uint32_t module_id, uint32_t func_id) {
  trace_event_t ev;
  ev.kind = TRACE_EVT_FUNC_ENTER;
  ev.module_id = module_id;
  ev.func_id = func_id;
  ev.aux_id = 0;
  ev.aux_val = 0;
  trace_record_event(ev);
}

NO_INSTRUMENT void trace_fn_exit(uint32_t module_id, uint32_t func_id) {
  trace_event_t ev;
  ev.kind = TRACE_EVT_FUNC_EXIT;
  ev.module_id = module_id;
  ev.func_id = func_id;
  ev.aux_id = 0;
  ev.aux_val = 0;
  trace_record_event(ev);
}

NO_INSTRUMENT void trace_branch(uint32_t module_id, uint32_t func_id,
                                uint32_t branch_id, int cond_true) {
  trace_event_t ev;
  ev.kind = TRACE_EVT_BRANCH;
  ev.module_id = module_id;
  ev.func_id = func_id;
  ev.aux_id = branch_id;
  ev.aux_val = cond_true ? 1 : 0;
  trace_record_event(ev);
}

NO_INSTRUMENT void trace_call_edge(uint32_t module_id, uint32_t from_func_id,
                                   uint32_t to_func_id, uint32_t call_id) {
  trace_event_t ev;
  ev.kind = TRACE_EVT_CALL;
  ev.module_id = module_id;
  ev.func_id = from_func_id;
  ev.aux_id = call_id;
  ev.aux_val = to_func_id;
  trace_record_event(ev);
}

NO_INSTRUMENT void trace_marker(uint32_t module_id, uint32_t func_id,
                                uint32_t marker_id) {
  trace_event_t ev;
  ev.kind = TRACE_EVT_MARKER;
  ev.module_id = module_id;
  ev.func_id = func_id;
  ev.aux_id = marker_id;
  ev.aux_val = 0;
  trace_record_event(ev);
}

static NO_INSTRUMENT void trace_runtime_flush(void) {
  const char *out = getenv("TRACE_RUNTIME_OUTPUT");
  if (!out || !*out)
    return;
  FILE *f = fopen(out, "w");
  if (!f)
    return;

  fprintf(f, "{\n  \"events\": [\n");
  for (size_t i = 0; i < g_event_count; ++i) {
    const trace_event_t *ev = &g_events[i];
    if (i > 0)
      fprintf(f, ",\n");

    fprintf(f,
            "    {\"kind\": %u, \"module_id\": %u, \"func_id\": %u, "
            "\"aux_id\": %u, \"aux_val1\": %d}",
            (unsigned)ev->kind, (unsigned)ev->module_id, (unsigned)ev->func_id,
            (unsigned)ev->aux_id, (int)ev->aux_val);
  }

  fprintf(f, "\n  ]\n}\n");

  fclose(f);
}

// clang -fPIC -c trace_runtime.c -o trace_runtime.o
// ar rcs trace_runtime.a trace_runtime.o