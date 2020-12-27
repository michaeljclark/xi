# Xi

_Xi_ (aka ξ), a search tool for the Unicode Character Database.

![xi](/images/xi.png)

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
