# Security Policy

## Project status

TrustForge is **pre-alpha**. No release exists, and the current code does not perform any verification. There are no supported versions yet. Security fixes will be backported according to a support policy published with the first release candidate.

## Reporting a vulnerability

Please **do not** report vulnerabilities in public issues, discussions or pull requests.

Report them privately through GitHub's private vulnerability reporting (the **"Report a vulnerability"** button on the repository's *Security* tab). A dedicated security contact will be published here before the first release candidate.

Please include:

- the affected component and version (or commit);
- a description of the issue and its impact;
- steps or a minimal input to reproduce it, such as a crafted manifest, artifact, repository or archive;
- any suggested mitigation.

We aim to acknowledge reports within 7 days (on a best-effort basis while the project is pre-alpha). We will keep you informed while we investigate, coordinate the disclosure date with you, and credit you unless you prefer to remain anonymous.

## What counts as a vulnerability

Because TrustForge's output is used to make trust decisions, we treat these as security issues, not ordinary bugs:

- any path by which TrustForge reports **VERIFIED**, **PASSED** or **MATCH** when the evidence does not support it, or hides missing or contradicting evidence;
- acceptance of a signature, certificate or identity that the configured trust policy does not allow;
- code execution, file access or network access outside the documented sandbox, caused by an artifact, manifest, repository, dependency or build output;
- path traversal, symlink following outside an artifact root, or unsafe handling of archives;
- parser differentials, crashes, hangs or unbounded resource use on untrusted input;
- terminal escape-sequence injection through untrusted strings.

The guarantees TrustForge does and does not provide are documented in [docs/threat-model.md](docs/threat-model.md) and [docs/limitations.md](docs/limitations.md). Behavior those documents list as out of scope, such as container escapes through kernel vulnerabilities, is not a TrustForge vulnerability. Reports that show the documentation understates a risk are still very welcome.
