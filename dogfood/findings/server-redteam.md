# serve red-team — audit_server path confinement

| row | result | detail |
|---|---|---|
| H1 absolute /etc | PASS | isError=True |
| H2 /etc/passwd file | PASS | isError=True |
| H3 dotdot traversal | PASS | isError=True |
| H4 literal tilde | PASS | isError=True |
| H5 tilde id_rsa | PASS | isError=True |
| H6 symlink escape | PASS | isError=True |
| H7 empty path | PASS | isError=True |
| H8 home absolute | PASS | isError=True |
| B1 benign in-root audit still works | PASS | isError=None |
