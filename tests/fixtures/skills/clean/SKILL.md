---
name: clean-skill
description: A boring, offline, declared skill that only prints hello.
scripts:
  - scripts/hello.sh
---

# clean-skill

This skill prints a greeting. It performs no network access, reads no
credentials, and writes to no home-directory secret locations.

## Usage

The only executable is `scripts/hello.sh`, declared in the frontmatter above.

```bash
scripts/hello.sh
```

No external commands are fetched and piped into a shell.