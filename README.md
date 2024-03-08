# ucred-rs

The **ucred** crate provides safe access to
[ucred(3C)](https://illumos.org/man/3C/ucred) objects and their associated
functions; e.g., [getpeerucred(3C)](https://illumos.org/man/3C/getpeerucred)
and [door_ucred(3C)](https://illumos.org/man/3C/door_ucred).  This facility
allows a program running on an [illumos](https://illumos.org) system to obtain
credential information from the process on the far end of a local socket, or a
door connection, or by providing an explicit process ID.

The crate also provides convenience routines for mapping user IDs and group IDs
to user and group names using the local
[passwd(5)](https://illumos.org/man/5/passwd) and
[group(5)](https://illumos.org/man/5/group) databases.  Note that (as mentioned
in the documentation) if a door or a socket terminates in a zone other than the
current zone, these mappings may not be correct.  Each zone has its own name
service databases and configuration; synchronising those databases with one
another is left to site-specific policies and systems.

## Licence

Unless otherwise noted, all components are licenced under the [Mozilla Public
License Version 2.0](./LICENSE).
