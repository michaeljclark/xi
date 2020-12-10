# xi

_xi_ (aka ξ), a search tool for the Unicode Character Database.

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
