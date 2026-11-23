# Third-Party Notices

`sudo-check` is licensed under the MIT License (see [LICENSE](./LICENSE)). It incorporates or references third-party source code, data snapshots, specifications, and Go module dependencies whose licenses and attributions are documented below.

---

## 1. Upstream `sudo` / `cvtsudoers` Reference Sources (`docs/reference/cvtsudoers-src/`)

The reference C implementation files retained in [docs/reference/cvtsudoers-src/](./docs/reference/cvtsudoers-src/) originate from the upstream `sudo` project (`https://www.sudo.ws/`, `https://github.com/sudo-project/sudo`) by Todd C. Miller and are used strictly as a reference for JSON schema parity and differential oracle testing.

Retained files:
- [cvtsudoers.c](./docs/reference/cvtsudoers-src/cvtsudoers.c) — Copyright (c) 2018-2023 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers.h](./docs/reference/cvtsudoers-src/cvtsudoers.h) — Copyright (c) 2018, 2021-2023 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers_csv.c](./docs/reference/cvtsudoers-src/cvtsudoers_csv.c) — Copyright (c) 2021-2024 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers_json.c](./docs/reference/cvtsudoers-src/cvtsudoers_json.c) — Copyright (c) 2013-2024 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers_ldif.c](./docs/reference/cvtsudoers-src/cvtsudoers_ldif.c) — Copyright (c) 2018-2024 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers_merge.c](./docs/reference/cvtsudoers-src/cvtsudoers_merge.c) — Copyright (c) 2021-2024 Todd C. Miller `<Todd.Miller@sudo.ws>`
- [cvtsudoers_pwutil.c](./docs/reference/cvtsudoers-src/cvtsudoers_pwutil.c) — Copyright (c) 1996, 1998-2005, 2007-2020, 2022-2025 Todd C. Miller `<Todd.Miller@sudo.ws>`

All seven files in [docs/reference/cvtsudoers-src/](./docs/reference/cvtsudoers-src/) are distributed under the **ISC License** (`SPDX-License-Identifier: ISC`):

```text
Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

Additional sponsorship notice from [cvtsudoers_pwutil.c](./docs/reference/cvtsudoers-src/cvtsudoers_pwutil.c):

```text
Sponsored in part by the Defense Advanced Research Projects
Agency (DARPA) and Air Force Research Laboratory, Air Force
Materiel Command, USAF, under agreement number F39502-99-1-0512.
```

---

## 2. GTFObins Database Snapshot (`pkg/gtfobins/database.json`)

The embedded executable capability catalog in [pkg/gtfobins/database.json](./pkg/gtfobins/database.json) is derived from the **GTFObins** project (`https://gtfobins.org/`, `https://github.com/GTFOBins/GTFOBins.github.io`, `https://gtfobins.org/api.json`), licensed under the MIT License.

---

## 3. Reference Corpus & Compliance Standards

- **Sudoers Differential & Stress-Test Corpus** ([testdata/corpus/](./testdata/corpus/README.md)): Collects public distribution default `sudoers` files, upstream `sudo-project/sudo` regression test cases, and public enterprise/cloud configuration examples for offline differential parity and fuzz/stress testing.
- **ANSSI BP-028 v2.0 Reference Guide** ([docs/reference/linux_configuration-en-v2.pdf](./docs/reference/linux_configuration-en-v2.pdf)): *Configuration Recommendations for a GNU/Linux System* published by the Agence nationale de la securite des systemes d'information (ANSSI).

---

## 4. Go Module Dependencies (`go.mod`)

Direct and indirect Go module dependencies declared in [go.mod](./go.mod):

| Module | Version | License |
| :--- | :--- | :--- |
| `github.com/go-pdf/fpdf` | `v0.9.0` | MIT License |
| `github.com/spf13/cobra` | `v1.10.2` | Apache License 2.0 |
| `github.com/spf13/pflag` | `v1.1.0` | BSD-3-Clause License |
| `github.com/inconshreveable/mousetrap` | `v1.1.0` | Apache License 2.0 |
| `go.yaml.in/yaml/v3` | `v3.0.6` | MIT License / Apache License 2.0 |
