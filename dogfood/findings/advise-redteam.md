# advise red-team — findings

advise exit: 0

| row | result | detail |
|---|---|---|
| P1 no-live-directive | FAIL | line 0 begins with a directive: '<!-- glassport:begin -->' |
| P2 single-fence-pair | FAIL | BEGIN×1, END×2 (expected 1/1) |
| P2 idempotent-rewrite | FAIL | rc2=1, stable=True |
| P3 homoglyph-defanged | FAIL | line 0 begins with a directive: '<!-- glassport:begin -->' |
| P4 no-raw-secret | PASS | no raw secret present |
| P5 no-snippet | FAIL | 'ignore previous instructions' present |
