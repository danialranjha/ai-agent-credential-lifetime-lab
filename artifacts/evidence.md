# File-lifetime evidence

Nine selected deterministic fixtures, two methods, eighteen rows. Not attack rates.
The consumer and reader use an explicitly replaced environment and the same OS user.
Both file modes are actual observed modes. A held descriptor is deliberately opened before consumption.

| Fixture | Persistent reader | Read then delete reader |
|---|---|---|
| before_644 | INVENTED_NONCREDENTIAL_MARKER_42 | INVENTED_NONCREDENTIAL_MARKER_42 |
| before_600 | INVENTED_NONCREDENTIAL_MARKER_42 | INVENTED_NONCREDENTIAL_MARKER_42 |
| after_644 | INVENTED_NONCREDENTIAL_MARKER_42 | (missing) |
| after_600 | INVENTED_NONCREDENTIAL_MARKER_42 | (missing) |
| held_descriptor_644 | INVENTED_NONCREDENTIAL_MARKER_42 | INVENTED_NONCREDENTIAL_MARKER_42 |
| held_descriptor_600 | INVENTED_NONCREDENTIAL_MARKER_42 | INVENTED_NONCREDENTIAL_MARKER_42 |
| missing | (missing) | (missing) |
| ordinary_file | ordinary work note | ordinary work note |
| second_consumer | INVENTED_NONCREDENTIAL_MARKER_42 | (missing) |

## Exact paired trace

after_600: create owned mode-0600 marker; replace child environment; consume marker; attempt later pathname read.
Persistent: consumer receives marker; later reader also receives marker; pathname remains.
Read then delete: consumer receives the same marker; later reader reports missing; pathname is absent.

## Limits visible in the same run

Before-consumption readers and readers holding an earlier descriptor receive the marker with both methods and both file modes.
The ordinary work note remains readable with both methods.
Missing marker: read-then-delete returns exit status 0 with empty stdout, because rm -f is the final command. Persistent cat returns 1. Exit 0 alone is not a credential-read success oracle.
Second consumption: persistent returns the marker again; read-then-delete returns empty stdout with status 0. This assay does not implement or verify any credential cache.

No timing race, live model, deployed workflow, isolation boundary, provider request or real secret was tested.
