# Xi

_Xi_ (aka ξ), a search tool for the Unicode Character Database.

## Usage Instructions

_Xi_ `unicode` subcommand indicates a search against the Unicode
Character Database. The search accepts boolean 'and' search terms
and quoted terms indicate exact match. The closing quote can be
omitted to accept what could be partially typed searches.

### Example Invocations

```
xi unicode green                # search for 'green'
xi unicode smiling              # search for 'smiling'
xi unicode "mu                  # search for 'mu' (exact matches)
xi unicode greek letter mu      # search for 'greek', letter' and 'mu'
xi unicode mathematical mu      # search for 'mathematical' and 'mu'
```

### Operating Systems

_Xi_ has been tested on the following operating systems:

- Windows 10 20H2
- Ubuntu 20.04 LTS
- macOS catalina 10.15.7
- FreeBSD 12.1-RELEASE

## Build Instructions

```
cmake -B build
cmake --build build
```

## Algorithm Details

_Xi_ implements the Rabin-Karp algorithm to find recurring substrings
within a string. It does this by recording a rolling hash code of all
combinations of substrings for all tokens in the character database.

There are currently two search methods:

- Brute Force
  - a brute force implementation searches through every row in the table.
    The brute force approach is faster for single queries, but each query
    needs to scan the full table.
- Rabin-Karp
  - a Rabin-Karp implementation searches for token hash table matches.
    The Rabin-Karp search is very fast but the indices need to be created
    so it is slower for the first query. This is the primary reason,
    to split the search into a search daemon and command line client. There
    is work in the `nub-protocol` branch to move the search engine into
    a background process that is queried over a named pipe.

To answer queries, hash codes are computed for all query terms which
are then used to find tokens in the hash table, which are collated then
filtered using the boolean _and_ combination of terms. The filter step
is needed because some token hits will refer to rows that only contain
a subset of all query terms.


## Nubs

_Xi_ supports a concept called _nubs_ which are session activation and
peer communication stubs. _Nubs_ allow an agent to create a session peer
process with a different lifecycle to its own, hence the name _nub_.

> cross-platform session peer activation stubs

Nubs eliminate the need to configure environment variables or modify
operating system launchers like _systemd_, _launchd_ and _services_.
Nubs allow splitting an app into a command-line agent and a separate
session peer process, with the session peer started by the command-line
tool. Subsequent invocations of the command-line tool will connect to a
previously created peer process.

### Xi Unicode Nub

_Xi_ uses nubs to create a process that caches the Rabin-Karp indices,
to allow it to answer queries more quickly because the index has been
cached. This makes subsequent invocations very fast. Queries in this
way can be answered in less than a millisecond.

_Example invocation of a search query:_

```
xi -t unicode blue
⻘	U+2ed8	CJK RADICAL BLUE
⾭	U+2fad	KANGXI RADICAL BLUE
💙	U+1f499	BLUE HEART
📘	U+1f4d8	BLUE BOOK
🔵	U+1f535	LARGE BLUE CIRCLE
🔷	U+1f537	LARGE BLUE DIAMOND
🔹	U+1f539	SMALL BLUE DIAMOND
🟦	U+1f7e6	LARGE BLUE SQUARE
🫐	U+1fad0	BLUEBERRIES
[nub-agent] search = 254μs
```

### Nub addresses

Nub addresses are composed using a SHA-256 hash of the components of
the argument vector including the terminating zero of each C string.
`<self>` is substituted for the executable name. The SHA-256 hash is
computed after any substitutions so that unique binary images have
unique addresses.

The following initialization code:

```
const char* args[] = { "<self>", "nub-server" };
xi_nub_server *c = xi_nub_server_new(ctx, 2, args);
```

Results in the following nub addresses:

|operating system|example nub address|
|---|---|
|Windows pipe|`\\.\pipe\Xi-1345c60535958c16a94dbbde8dfdbf86b260670a9afb9ca1b9de4747ae309234`|
|UNIX socket|`@Xi-e21c0ba1c40d379e35292716e290aa6761184e9fba5f30b274636d51b15a2688`|

### Nub Locking

Nubs use a locking protocol to ensure that only a single process is
launched. When a nub agent attempts to connect to the server. if there
is no answer they will create a semaphore, writing its id to a file,
a leader will be chosen to fork the nub child process and all agents
will then wait on their semaphore. When the server has started, it will
read the list of semaphores and signal them, waking up all of the agents.

## Licenses

_Xi_ is released under the ISC license. The Unicode Character Database, in
particular the [UnicodeData.txt](data/14.0.0/UnicodeData.txt) file are licensed
under these [terms of use](https://www.unicode.org/terms_of_use.html). © 2021
Unicode®, Inc. Unicode and the Unicode Logo are registered trademarks of
Unicode, Inc. in the U.S. and other countries.
