# AI-agent credential-file lifetime lab

Deleting a file after consuming its contents changes later pathname reads. It does not undo an earlier read or revoke a descriptor already open. This lab measures that distinction with harmless invented markers, real POSIX files and actual child processes.

No AI model, provider, live workflow, real credential or network is used. A shell consumer stands in only for the file-reading step; it does not implement the agent's credential cache.

## Hypothesis and threat model

For a reader running as the file owner, mode 0600 still permits reading the file. An explicitly replaced environment does not remove bytes already stored in that file. Reading and unlinking the file prevents a later read by its pathname after successful removal, while a read before consumption or through an earlier-open descriptor still returns the bytes.

Assume the reader can access the generated file as the same OS user at the specified time. Opening a descriptor before consumption is an explicit extra access assumption, not a demonstrated model attack. The OS, harness, fixture creation, interpreter and shell remain trusted. The harness opens the descriptor and passes it to the reader deliberately. No privilege change, process-memory read or race is attempted.

Everything resides inside a fresh temporary directory, including a synthetic HOME. No real home directory or agent configuration is inspected. The reader and consumer receive only the synthetic HOME and a fixed PATH. The script accepts no external target, file path or command. Outputs contain only public invented values.

## Setup and exact commands

Requires Python 3.10+ on POSIX with `/bin/sh`, `/bin/cat`, `/bin/rm` and descriptor passing. Validated on macOS with Python 3.12.4. No packages or installation required.

```sh
python3 experiment.py
python3 -m unittest discover -s tests -v
python3 run_checks.py
```

These regenerate [run.json](artifacts/run.json), [evidence.md](artifacts/evidence.md) and [checks.json](artifacts/checks.json). Temporary fixtures are removed after each case. Random paths, timestamps and OS user IDs are excluded from artifacts, so runs are byte reproducible in the validated environment.

## Results

Nine selected fixtures, two methods, eighteen rows. These are deterministic cases, not attack rates or independent vulnerability samples.

| Reader timing / control | Persistent | Read then delete |
|---|---|---|
| Before consumption, 0644 and 0600 | Marker read | Marker read |
| After consumption, 0644 and 0600 | Marker read | Path missing |
| Descriptor opened before consumption, both modes | Marker read | Marker read despite absent path |
| Ordinary work file after consumption | Note read | Same note read |
| Marker absent from start | Empty consumer output, status 1 | Empty consumer output, status 0 |
| Second consumption | Marker returned again | Empty output, status 0 |

Both methods deliver the same invented marker to the first consumer whenever the fixture exists. Ten tests pass. Two deliberate faults, skipping removal and suppressing every reader result, each produce four test failures and zero errors. The ordinary-work-file control prevents interpreting a broken reader as effective protection.

## Technical walkthrough

### Source-grounded question

[Stock-Trek issue 66](https://github.com/Stock-Trek/agent-workflows/issues/66) reported provider keys embedded in readable agent configuration. It is closed. [PR 67](https://github.com/Stock-Trek/agent-workflows/pull/67) merged on October 14, 2026 at 21:15:54 UTC, merge `598d134db313acdb2948e242bea26678e57b8159`.

The [pinned setup file](https://github.com/Stock-Trek/agent-workflows/blob/598d134db313acdb2948e242bea26678e57b8159/.github/actions/set-up-pi-models/action.yml) removes embedded provider keys and configures commands that read and then remove short-lived files. Its comments assert that Pi caches the returned value. This lab does not verify caching, startup order or all deployed access paths. Source blob `707d88b4feb43c4ceb6f41912f306d3188bd8984`, 3818 bytes, was independently verified against Git's blob hash. The [pinned invocation file](https://github.com/Stock-Trek/agent-workflows/blob/598d134db313acdb2948e242bea26678e57b8159/.github/actions/invoke-pi/action.yml) stages only the selected provider's file. No upstream workflow is executed or redistributed.

The experiment independently implements the basic shell distinction using a synthetic positional file argument:

```sh
# Persistent
/bin/cat "$1" 2>/dev/null
# Read then delete
/bin/cat "$1" 2>/dev/null; /bin/rm -f "$1"
```

This is a file-semantics assay inspired by the merged change, not a full reproduction of that implementation or evidence of an exploitable flaw in its current deployment.

### Exact ordering and oracle

For `after_600`, the harness creates an owned mode-0600 file containing `INVENTED_NONCREDENTIAL_MARKER_42`. It starts the consumer with a replaced environment. After the consumer exits, it starts the same-user reader. Persistent returns the marker to both. Read then delete returns it to the consumer, removes the pathname and yields `missing` to the reader.

For `held_descriptor_600`, the harness opens the file before consumption, passes that descriptor to the later child, and reads it only after consumption. Removing the directory entry does not invalidate that open descriptor. There is no simultaneous execution or probabilistic race in this counterexample.

The oracle compares actual captured bytes, not a success label. When the marker is missing, the read-then-delete shell command exits 0 because its final `rm -f` succeeds. It has returned no marker. That is why a startup check must verify expected nonempty output rather than only command status. No actual provider authentication is attempted.

### Honest limits and supported check

This does not demonstrate prompt injection, credential exfiltration, model persuasion, sandbox escape, or a production fix. The fixture marker is not a working key. Before-consumption access and inherited descriptors are assumed. File ownership is unchanged; 0600 can restrict other users but does not exclude the owner. Other-user enforcement is not tested.

The experiment has no provider cache. Its empty second-consumption result exposes why cache behavior and request ordering need separate validation. Deletion is not secure erasure and does not clear memory or revoke access already obtained. Removal failure, filesystem races, hard links, backups, child-process memory and alternate credential copies are not covered.

If relying on read-then-delete, test that the intended consumer receives the value, removal succeeds before less-trusted readers start, and subsequent pathname reads fail. Test the ordinary work path as well. Treat file lifetime as a limited defense; use a separately validated isolation design when same-user access before consumption or through existing handles is in scope.
