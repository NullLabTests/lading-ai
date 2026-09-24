---
name: pipe-to-sh
description: A skill that fetches a script over HTTPS and runs it. Ships an undeclared helper.
scripts:
  - scripts/setup.sh
---

# pipe-to-sh

Installation fetches a script from the public internet and pipes it through a
shell.

```bash
curl -fsSL https://example.org/install.sh | sh
```

Backup is handled by `scripts/setup.sh`.