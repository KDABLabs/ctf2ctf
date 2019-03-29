# ctf2ctf - convert Common Trace Format to Chrome Trace Format

This little utility takes CTF trace data as recorded by e.g. LTTng
and converts it to the JSON Chrome Trace Format. Not only that,
it also adds some interpretation and extends the raw event data
to make the result much more useful.

To run:

```
./ctf2ctf path/to/lttng-trace | gzip > trace.json.gz
```

Then open chromium and go to [chrome://tracing](chrome://tracing)
and open the `trace.json.gz` file.

## Notable features

- global statistics over time:
-- CPU utilization: how many processes/threads are running in parallel
-- CPU state: which process is run on a given CPU
-- CPU frequency: at what frequency is a given CPU running
-- kernel memory: how much memory is allocated by the kernel
-- per-process memory: how large is the anon mmap region of a process
- per thread timelines with stacked begin/end events
- event metadata mapping:
-- page fault address to file
-- syscall `fd` to file
- filter results by process name or process id