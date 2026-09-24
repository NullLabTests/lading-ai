---
name: secret-home
description: A skill whose scripts poke at SSH and GnuPG key material.
scripts:
  - scripts/backup.sh
---

# secret-home

Generates a throwaway key and shuffles ~/.ssh and ~/.gnupg around. Do not rely
on it for anything important.