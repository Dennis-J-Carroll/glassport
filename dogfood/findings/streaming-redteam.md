# streaming red-team — tail_only surfacing

| row | result | detail |
|---|---|---|
| S1 summarize JSON completeness | PASS | completeness=partial_tail_only |
| S2 summarize stderr WARN | PASS | 'WARN: log ingested tail-only — file exceeded the tail cap; t' |
| R1 report PARTIAL banner | PASS | len=6974 |
| W1 fingerprint tail_only flag | PASS | tail_only=True |
| W2 drift low-confidence notice | PASS | kinds=['tail_only_partial'] |
| C1 small log stays complete | PASS |  |
