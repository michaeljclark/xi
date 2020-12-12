/*
 * xi (aka ξ), a search tool for the Unicode Character Database.
 *
 * Copyright (c) 2020 Michael Clark <michaeljclark@mac.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>

#include <map>
#include <set>
#include <chrono>
#include <vector>
#include <string>
#include <utility>
#include <algorithm>

#include "utf8.h"
#include "hashmap.h"

/*
 * xi (aka ξ), a search tool for the Unicode Character Database.
 */

using namespace std::chrono;

using string = std::string;
template <typename T> using vector = std::vector<T>;
template <typename K,typename V> using pair = std::pair<K,V>;
template <typename K,typename V> using map = std::map<K,V>;

static const char* unicode_data_file = "data/13.0.0/UnicodeData.txt";
static bool help_text = false;
static bool debug_enabled = false;
static bool optimized_search = true;
vector<string> unicode_search_terms;

/*
 * schema for UnicodeData.txt from Unicode Character Database (UCD.zip)
 */

struct data {
    /*  0 */ uint32_t Code;
    /*  1 */ string Name;
    /*  2 */ string General_Category;
    /*  3 */ string Canonical_Combining_Class;
    /*  4 */ string Bidi_Class;
    /*  5 */ string Decomposition_Type;
    /*  6 */ string Decomposition_Mapping;
    /*  7 */ string Numeric_Type;
    /*  8 */ string Numeric_Value;
    /*  9 */ string Bidi_Mirrored;
    /* 10 */ string Unicode_1_Name;
    /* 11 */ string ISO_Comment;
    /* 12 */ string Simple_Uppercase_Mapping;
    /* 13 */ string Simple_Lowercase_Mapping;
    /* 14 */ string Simple_Titlecase_Mapping;
};

/*
 * utilities for reading the unicode character database
 */

enum split_flags { none = 0x0, inc_sep = 0x1, inc_empty = 0x2 };

static vector<string> split(string str, string sep, split_flags flags = none)
{
    size_t i, j = 0;
    vector<string> comps;
    const bool inc_sep = flags & split_flags::inc_sep;
    const bool inc_empty = flags & split_flags::inc_empty;
    while ((i = str.find_first_of(sep, j)) != string::npos) {
        if ((inc_empty) || i - j > 0) comps.push_back(str.substr(j, i - j));
        if ((inc_sep)) comps.push_back(str.substr(i, sep.size()));
        j = i + sep.size();
    }
    if (inc_empty || str.size() - j > 0) {
        comps.push_back(str.substr(j, str.size() - j));
    }
    return comps;
}

bool parse_codepoint(string str, unsigned long &val)
{
    char *endptr = nullptr;
    val = strtoul(str.c_str(), &endptr, 16);
    return (*endptr == '\0');
}

vector<data> read_unicode_data()
{
    // 0000;<control>;Cc;0;BN;;;;;N;NULL;;;;
    vector<data> data;
    FILE *f;
    char buf[256];
    const char* p;

    if ((f = fopen(unicode_data_file, "r")) == nullptr) {
        fprintf(stderr, "fopen: %s\n", strerror(errno));
        exit(1);
    }
    while((p = fgets(buf, sizeof(buf), f)) != nullptr) {
        string l(p);
        if (l.size() == 0) continue;
        vector<string> d = split(l, ";", split_flags::inc_empty);
        unsigned long codepoint;
        if (!parse_codepoint(d[0], codepoint)) abort();
        data.push_back({
            (uint32_t)codepoint,
            d[1], d[2], d[3], d[4], d[5], d[6], d[7],
            d[8], d[9], d[10], d[11], d[12], d[13], d[14]
        });
    }
    fclose(f);

    return data;
}

/*
 * Rabin-Karb rolling hash substring hashtable
 */

template <typename Size, typename Sym>
struct hash_fnv1a
{
    static const Size I = 0xcbf29ce484222325;
    static const Size P = 0x100000001b3;

    Size h;

    hash_fnv1a() : h(I) {}
    inline void add(Sym s) { h ^= s; h *= P; }
    Size val() { return h; }
};

struct subhash_ent { int line; int tok; int offset; int len; };
typedef zedland::hashmap<size_t,vector<subhash_ent>> subhash_map;
typedef pair<size_t,vector<subhash_ent>> subhash_pair;

static void index_list(subhash_map &index, vector<vector<string>> &tokens)
{
    for (int i = 0; i < (int)tokens.size(); i++) {
        for (int j = 0; j < (int)tokens[i].size(); j++) {
            for (int k = 0; k < (int)tokens[i][j].size(); k++) {
                hash_fnv1a<size_t,char> hf;
                for (int l = k; l < (int)tokens[i][j].size(); l++) {
                    hf.add(tokens[i][j][l]);
                    auto ri = index.find(hf.h);
                    if (ri == index.end()) {
                        ri = index.insert
                            (subhash_pair(hf.h, vector<subhash_ent>()));
                    }
                    ri->second.push_back(subhash_ent{i,j,k,l-k+1});
                }
            }
        }
    }
}

/*
 * unicode data search - using linear scan
 */

static void do_search_brute_force(vector<string> terms)
{
    /*
     * load data, tokenize and convert to lower case
     */
    const auto t1 = high_resolution_clock::now();
    vector<data> data = read_unicode_data();
    vector<vector<string>> tokens;
    size_t byte_count = 0;
    for (size_t i = 0; i < data.size(); i++) {
        byte_count += data[i].Name.size();
        vector<string> tl = split(data[i].Name.data(), " ");
        for (auto &name : tl) {
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c){ return std::tolower(c); });
        }
        tokens.push_back(tl);
    }
    const auto t2 = high_resolution_clock::now();

    /*
     * convert search terms to lower case
     */
    for (auto &term : terms) {
        std::transform(term.begin(), term.end(), term.begin(),
            [](unsigned char c){ return std::tolower(c); });
    }

    /*
     * brute force search all rows for matches
     */
    for (size_t i = 0; i < data.size(); i++) {
        size_t matches = 0;
        for (auto &term : terms) {
            bool match = false;
            if (term.size() > 1 && term.front() == '\"') {
                /* don't require close quotes for partially typed queries */
                bool has_close_quote = term.back() == '\"';
                size_t quote_len = term.size() - 1 - has_close_quote;
                for (auto &token : tokens[i]) {
                    match |= (token == term.substr(1, quote_len));
                }
            } else {
                for (auto &token : tokens[i]) {
                    auto o = token.find(term);
                    match |= (o != string::npos);
                }
            }
            if (match) matches++;
        }
        if (matches == terms.size()) {
            char buf[5];
            utf32_to_utf8(buf, sizeof(buf), data[i].Code);
            printf("%s\tU+%04x\t%s\n", buf, data[i].Code, data[i].Name.c_str());
        }
    }

    if (!debug_enabled) return;

    /*
     * print timings
     */
    const auto t3 = high_resolution_clock::now();
    auto tl = duration_cast<nanoseconds>(t2 - t1).count();
    auto ts = duration_cast<nanoseconds>(t3 - t2).count();
    printf("[Brute-Force] load = %.fμs, search = %.fμs, rows = %zu, bytes = %zu\n",
        tl / 1e3, ts / 1e3, data.size(), byte_count);
}

/*
 * unicode data search - using rolling hash index
 */

static void do_search_rabin_karp(vector<string> terms)
{
    /*
     * load data, tokenize and convert to lower case
     */
    const auto t1 = high_resolution_clock::now();
    vector<data> data = read_unicode_data();
    vector<vector<string>> tokens;
    size_t byte_count = 0;
    for (size_t i = 0; i < data.size(); i++) {
        byte_count += data[i].Name.size();
        vector<string> tl = split(data[i].Name.data(), " ");
        for (auto &name : tl) {
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c){ return std::tolower(c); });
        }
        tokens.push_back(tl);
    }

    /*
     * create Rabin-Karp substring hash indices
     */
    subhash_map index;
    index_list(index, tokens);
    const auto t2 = high_resolution_clock::now();

    /*
     * convert search terms to lower case
     */
    for (auto &term : terms) {
        std::transform(term.begin(), term.end(), term.begin(),
            [](unsigned char c){ return std::tolower(c); });
    }

    /*
     * search the tokenized Rabin-Karp hash table for token matches
     *
     * search result map containing: { row -> { term -> count }
     */
    map<int,zedland::hashmap<int,int>> results;
    for (size_t t = 0; t < terms.size(); t++)
    {
        auto &term = terms[t];
        hash_fnv1a<size_t,char> hf;
        bool needs_exact = false, is_exact = false;;
        if (term.size() > 1 && term.front() == '\"') {
            needs_exact = true;
            /* don't require close quotes for partially typed queries */
            bool has_close_quote = term.back() == '\"';
            for (size_t i = 1; i < term.size() - has_close_quote; i++) {
                hf.add(term[i]);
            }
        } else {
            for (size_t i = 0; i < term.size(); i++) {
                hf.add(term[i]);
            }
        }
        auto ri = index.find(hf.h);
        if (ri == index.end()) continue;

        for (size_t j = 0; j < ri->second.size(); j++) {
            subhash_ent e = ri->second[j];
            string s = tokens[e.line][e.tok].substr(e.offset,e.len);
            is_exact = (e.offset == 0 && e.len == tokens[e.line][e.tok].size());
            auto si = results.find(e.line);
            if (!needs_exact || (needs_exact && is_exact)) {
                /* create { term -> count } map per matched line */
                if (si == results.end()) {
                    si = results.insert(results.end(),
                        pair<int,zedland::hashmap<int,int>>
                        (e.line,zedland::hashmap<int,int>()));
                }
                /* count occurances of each term */
                si->second[(int)t]++;
            }
        }
    }

    /*
     * loop through results which are organised by row matched
     *
     * print results for lines where the sum of matches is equal
     * to the number of terms. this means each term must match at
     * least once but can match in the same column more than once.
     * all terms must be covered.
     */
    for (auto ri = results.begin(); ri != results.end(); ri++)
    {
        int i = ri->first;
        if (ri->second.size() == terms.size()) {
            char buf[5];
            utf32_to_utf8(buf, sizeof(buf), data[i].Code);
            printf("%s\tU+%04x\t%s\n", buf, data[i].Code, data[i].Name.c_str());
        }
    }

    if (!debug_enabled) return;

    /*
     * print timings
     */
    const auto t3 = high_resolution_clock::now();
    auto tl = duration_cast<nanoseconds>(t2 - t1).count();
    auto ts = duration_cast<nanoseconds>(t3 - t2).count();
    printf("[Rabin-Karp] load = %.fμs, search = %.fμs, rows = %zu, bytes = %zu\n",
        tl / 1e3, ts / 1e3, data.size(), byte_count);
}

/*
 * command line options
 */

void print_help(int argc, char **argv)
{
    fprintf(stderr,
        "Usage: %s [options] [command] <command-parameters>\n"
        "\n"
        "Commands:\n"
        "  unicode [<term>]+            search unicode character database\n"
        "\n"
        "Examples:\n"
        "  unicode green                # search for 'green'\n"
        "  unicode smiling              # search for 'smiling'\n"
        "  unicode \"mu                  # search for 'mu' (exact matches)\n"
        "  unicode greek letter mu      # search for 'greek', letter' and 'mu'\n"
        "  unicode mathematical mu      # search for 'mathematical' and 'mu'\n"
        "\n"
        "Options:\n"
        "  -u, --data-file <name>       unicode data file\n"
        "  -d, --debug                  enable search debug and timings\n"
        "  -x, --brute-force            disable search optimization\n"
        "  -h, --help                   command line help\n",
        argv[0]);
}

bool check_param(bool cond, const char *param)
{
    if (cond) {
        printf("error: %s requires parameter\n", param);
    }
    return (help_text = cond);
}

bool match_option(const char *arg, const char *opt, const char *longopt)
{
    return strcmp(arg, opt) == 0 || strcmp(arg, longopt) == 0;
}

bool match_command(const char *arg, const char *cmd)
{
    return strcmp(arg, cmd) == 0;
}

bool parse_unicode_search(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "error: unicode search missing terms\n");
        return false;
    }
    int i = 1;
    while (i < argc) {
        unicode_search_terms.push_back(argv[i++]);
    }
    return true;
}

bool parse_options(int argc, char **argv)
{
    int i = 1;
    while (i < argc) {
        if (match_option(argv[i], "-u", "--unicode-data")) {
            if (check_param(++i == argc, "--unicode-data")) break;
            unicode_data_file = argv[i++];
        } else if (match_option(argv[i], "-d", "--debug")) {
            debug_enabled = true;
            i++;
        } else if (match_option(argv[i], "-x", "--brute-force")) {
            optimized_search = false;
            i++;
        } else if (match_option(argv[i], "-h", "--help")) {
            return false;
        } else {
            break;
        }
    }

    if (i >= argc) {
        fprintf(stderr, "error: expecting command\n");
    } else if (match_command(argv[i], "unicode")) {
        return parse_unicode_search(argc-i, argv+i);
    } else {
        fprintf(stderr, "error: unknown command\n");
    }

    return false;
}

/*
 * main program
 */

int main(int argc, char **argv)
{
    if (!parse_options(argc, argv)) {
        print_help(argc, argv);
        exit(1);
    }

    if (unicode_search_terms.size()) {
        if (optimized_search) {
            do_search_rabin_karp(unicode_search_terms);
        } else {
            do_search_brute_force(unicode_search_terms);
        }
    }
}
