# Three Vulnerabilities in Journald Forward Secure Log Sealing

This repository contains the accompanying code for the publication "Secure Logging in between Theory and Practice: Security Analysis of the Implementation of Forward Secure Log Sealing in Journald" ([in this repository](journald-publication.pdf) or [on eprint](https://ia.cr/2023/867)). For details on the individual vulnerabilities and theoretical background we refer to the publication.
The three vulnerabilities mentioned are:

## [CVE-2023-31439](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31439)
This vulnerability allows forging arbitrary logs. This vulnerability is caused by a missing check. A patch suggestion is available in [CVE-2023-31439.patch](CVE-2023-31439.patch).

## [CVE-2023-31438](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31438)
This vulnerability allows unnoticed truncation of logs. It can be partly mitigated by [CVE-2023-31438-incomplete.patch](CVE-2023-31438-incomplete.patch).

## [CVE-2023-31437](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-31437)
This vulnerability allows hiding some log entries from log output displayed using filters like `journalctl -u "systemd-*.service"`.


This project can be built and imported into an IDE as a regular gradle project.

The attack described in the publication can be reproduced by running [`Attacker.main`](src/main/java/journald/Attacker.java#L23).
To use a different systemd implementation as target, adjust [`JournalSystem#createInstance`](src/main/java/journald/JournalSystem.java#L170) and provide the path to the desired build directory in there.
