"""
console_html.py — the Glassport Console frontend, one self-contained
HTML document. Lives in a module constant so `pip install .` ships it
with zero packaging configuration and the page can never 404.

No external requests of any kind (fonts, CDNs, analytics): the console
must work air-gapped, and a page that phones home from a security tool
would be its own finding.
"""

CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>glassport console</title>
</head>
<body>
<h1>glassport console</h1>
<p>placeholder — CRT frontend lands in the next commit</p>
</body>
</html>
"""
