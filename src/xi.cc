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
#include <cerrno>
#include <cctype>
#include <cinttypes>

#include <map>
#include <set>
#include <chrono>
#include <vector>
#include <string>
#include <utility>
#include <algorithm>

#include "utf8.h"
#include "hashmap.h"
#include "stdendian.h"
#include "xi_nub.h"
#include "xi_common.h"

/*
 * xi (aka ξ), a search tool for the Unicode Character Database.
 */

using namespace std::chrono;

using string = std::string;
template <typename T> using vector = std::vector<T>;
template <typename K,typename V> using pair = std::pair<K,V>;
template <typename K,typename V> using map = std::map<K,V>;

bool _debug_enabled;

static const char* unicode_data_file = "data/14.0.0/UnicodeData.txt";
static bool help_text = false;
static bool standalone_search = false;
static bool nub_server = false;
static bool timings_enabled = false;
static bool optimized_search = true;
static vector<string> unicode_search_terms;
static string unicode_numeric_term;

/*
 * schema for UnicodeData.txt from Unicode Character Database (UCD.zip)
 */

struct unicode_data {
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

static string join(vector<string> comps, string sep, size_t start, size_t end)
{
    string str;
    for (size_t i = start; i != end; i++) {
        if (i != start) {
            str.append(sep);
        }
        str.append(comps[i]);
    }
    return str;
}

bool parse_codepoint(string str, unsigned long &val)
{
    char *endptr = nullptr;
    val = strtoul(str.c_str(), &endptr, 16);
    return (*endptr == '\0');
}

vector<unicode_data> read_unicode_data()
{
    // 0000;<control>;Cc;0;BN;;;;;N;NULL;;;;
    vector<unicode_data> data;
    FILE *f;
    char buf[256];
    const char* p;

    if ((f = fopen(unicode_data_file, "r")) == nullptr) {
        _panic("fopen: %s\n", strerror(errno));
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

static void index_rabin_karp(subhash_map &index, vector<vector<string>> &tokens)
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

static void tokenize_data(vector<unicode_data> &data,
    vector<vector<string>> &tokens)
{
    for (size_t i = 0; i < data.size(); i++) {
        vector<string> tl = split(data[i].Name.data(), " ");
        for (auto &name : tl) {
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c){ return std::tolower(c); });
        }
        tokens.push_back(tl);
    }
}

static void lowercase_terms(vector<string> &terms)
{
    for (auto &term : terms) {
        std::transform(term.begin(), term.end(), term.begin(),
            [](unsigned char c){ return std::tolower(c); });
    }
}

/*
 * unicode data search - using linear scan
 */

static vector<unicode_data> xi_search_brute_force(vector<unicode_data> &data,
    vector<vector<string>> &tokens, vector<string> terms)
{
    lowercase_terms(terms);

    /*
     * brute force search all rows for matches
     */

    vector<unicode_data> results;
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
            results.push_back(data[i]);
        }
    }

    return results;
}

static vector<unicode_data> xi_search_brute_force(vector<string> terms)
{
    /*
     * load and tokenize unicode data
     */
    const auto t1 = high_resolution_clock::now();
    vector<vector<string>> tokens;
    vector<unicode_data> data = read_unicode_data();
    tokenize_data(data, tokens);

    /*
     * perform search
     */
    const auto t2 = high_resolution_clock::now();
    vector<unicode_data> results = xi_search_brute_force(data, tokens, terms);
    const auto t3 = high_resolution_clock::now();

    /*
     * print timings
     */
    if (timings_enabled)
    {
        auto tl = duration_cast<nanoseconds>(t2 - t1).count();
        auto ts = duration_cast<nanoseconds>(t3 - t2).count();
        printf("[Brute-Force] load = %.fμs, search = %.fμs\n",
               tl / 1e3, ts / 1e3);
    }

    return results;
}

/*
 * unicode data search - using rolling hash index
 */

static vector<unicode_data> xi_search_rabin_karp(vector<unicode_data> &data,
    vector<vector<string>> &tokens, subhash_map &index, vector<string> terms)
{
    lowercase_terms(terms);

    /*
     * search the tokenized Rabin-Karp hash table for token matches
     *
     * search result map containing: { row -> { term -> count }
     */

    map<int,zedland::hashmap<int,int>> matches;
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
            auto si = matches.find(e.line);
            if (!needs_exact || (needs_exact && is_exact)) {
                /* create { term -> count } map per matched line */
                if (si == matches.end()) {
                    si = matches.insert(matches.end(),
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
    vector<unicode_data> results;
    for (auto ri = matches.begin(); ri != matches.end(); ri++)
    {
        int i = ri->first;
        if (ri->second.size() == terms.size()) {
            results.push_back(data[i]);
        }
    }

    return results;
}

static vector<unicode_data> xi_search_rabin_karp(vector<string> terms)
{
    /*
     * load, tokenize and index unicode data
     */
    const auto t1 = high_resolution_clock::now();
    subhash_map index;
    vector<vector<string>> tokens;
    vector<unicode_data> data = read_unicode_data();
    tokenize_data(data, tokens);
    index_rabin_karp(index, tokens);

    /*
     * perform search
     */
    const auto t2 = high_resolution_clock::now();
    vector<unicode_data> results = xi_search_rabin_karp(data, tokens, index, terms);
    const auto t3 = high_resolution_clock::now();

    /*
     * print timings
     */
    if (timings_enabled)
    {
        const auto t3 = high_resolution_clock::now();
        auto tl = duration_cast<nanoseconds>(t2 - t1).count();
        auto ts = duration_cast<nanoseconds>(t3 - t2).count();
        printf("[Rabin-Karp] load = %.fμs, search = %.fμs\n",
            tl / 1e3, ts / 1e3);
    }

    return results;
}

int64_t parse_value(const char* valstr)
{
    int64_t val;
    char *endptr = nullptr;
    if (strncmp(valstr, "0x", 2) == 0) {
        val = strtoull(valstr + 2, &endptr, 16);
    } else if (strncmp(valstr, "0b", 2) == 0) {
        val = strtoull(valstr + 2, &endptr, 2);
    } else {
        val = strtoull(valstr, &endptr, 10);
    }
    return val;
}

static vector<unicode_data> xi_codepoint_lookup(string term)
{
    /*
     * load unicode data
     */
    vector<unicode_data> data = read_unicode_data();

    /*
     * perform lookup
     */
    vector<unicode_data> results;
    uint32_t lookup_code = (int32_t)parse_value(term.c_str());
    for (size_t i = 0; i < data.size(); i++) {
        size_t matches = 0;
        if (data[i].Code == lookup_code) {
            results.push_back(data[i]);
        }
    }

    return results;
}

void xi_print_results(vector<unicode_data> data)
{
#if defined OS_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
#endif
    for (size_t i = 0; i < data.size(); i++) {
        char buf[5];
        utf32_to_utf8(buf, sizeof(buf), data[i].Code);
        printf("%s\tU+%04x\t%s\n", buf, data[i].Code, data[i].Name.c_str());
    }
}

/*
 * xi channel
 */

struct xi_channel
{
    enum { buf_size = 32768 };

    struct span { void *data; size_t length; };

    char buf[buf_size];
    size_t offset;
    size_t length;
    bool closing;

    template <typename INT, typename SWAP> size_t write_int(INT num, SWAP f);
    size_t write_int8(int8_t num) { return write_int<int8_t>(num,le8); }
    size_t write_int16(int16_t num) { return write_int<int16_t>(num,le16); }
    size_t write_int32(int32_t num) { return write_int<int32_t>(num,le32); }
    size_t write_int64(int64_t num) { return write_int<int64_t>(num,le64); }
    size_t write_string(const char *s, size_t len);

    template <typename INT, typename SWAP> size_t read_int(INT *num, SWAP f);
    size_t read_int8(int8_t *num) { return read_int<int8_t>(num,le8); }
    size_t read_int16(int16_t *num) { return read_int<int16_t>(num,le16); }
    size_t read_int32(int32_t *num) { return read_int<int32_t>(num,le32); }
    size_t read_int64(int64_t *num) { return read_int<int64_t>(num,le64); }
    size_t read_string(char *s, size_t buf_len, size_t *str_len);

    void reset()
    {
        offset = 0;
        length = sizeof(buf);
    }

    void copy_input(struct span); /* call inside read callback */
    struct span copy_output(); /* call before write call */
    struct span copy_remaining(); /* call before read call */
};

template <typename INT, typename SWAP> size_t xi_channel::write_int(INT num, SWAP f)
{
    if (offset + sizeof(num) > length) return 0;
    INT t = f(num);
    memcpy(&buf[offset], &t, sizeof(INT));
    _debug_func("bits=%zu, offset=%zu, value=%lld\n",
                sizeof(num)<<3, offset, (long long)num);
    offset += sizeof(num);
    return sizeof(num);
}

size_t xi_channel::write_string(const char *s, size_t len)
{
    size_t ret = write_int64(len);
    if (ret == 0 || offset + len > length) return 0;
    memcpy(&buf[offset], s, len);
    _debug_func("length=%zu, offset=%zu, value=\"%s\"\n",
                len, offset, string(&buf[offset], len).c_str());
    offset += len;
    return len + ret;
}

template <typename INT, typename SWAP> size_t xi_channel::read_int(INT *num, SWAP f)
{
    if (offset + sizeof(num) > length) return 0;
    INT t;
    memcpy(&t, &buf[offset], sizeof(INT));
    *num = f(t);
    _debug_func("bits=%zu, offset=%zu, value=%lld\n",
                sizeof(num)<<3, offset, (long long)*num);
    offset += sizeof(*num);
    return sizeof(*num);
}

size_t xi_channel::read_string(char *s, size_t buf_len, size_t *str_len)
{
    int64_t len64;
    size_t ret = read_int64(&len64);
    if (ret == 0 || offset + len64 > length) return 0;
    if ((size_t)len64 > buf_len) len64 = buf_len;
    memcpy(s, &buf[offset], len64);
    _debug_func("length=%" PRIu64 ", offset=%zu, value=\"%s\"\n",
                len64, offset, string(&buf[offset], len64).c_str());
    offset += len64;
    if (str_len) *str_len = len64;
    return len64 + ret;
}

void xi_channel::copy_input(struct span input)
{
    size_t copy_len = input.length;
    if (offset + copy_len > length) copy_len = length - offset;
    if (input.data != buf + offset) {
        memmove(buf + offset, input.data, copy_len);
    }
}

struct xi_channel::span xi_channel::copy_output()
{
    return xi_channel::span{&buf[0], offset };
}

struct xi_channel::span xi_channel::copy_remaining()
{
    return xi_channel::span{&buf[offset], length-offset };
}


/*
 * xi client
 */

static void xi_client_close_cb(xi_nub_ch *nch, xi_nub_error err)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: close(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_mark();

    delete ch;
}

static void xi_client_request_write_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len);

static void xi_client_response_read_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: read(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_func("ch=%s, len=%zu\n", xi_nub_io_get_identity(nch), len);

    ch->copy_input(xi_channel::span{buf, len});

    /* place to store results */
    vector<unicode_data> r;

    /* parse response */
    int64_t nitems;
    ch->read_int64(&nitems);
    r.resize(nitems);
    for (auto &d : r) {
        int32_t codepoint = 0;
        size_t str_len = 0;
        char str_buf[1024];
        ch->read_int32(&codepoint);
        d.Code = codepoint;
        ch->read_string(str_buf, sizeof(str_buf), &str_len);
        d.Name = string(str_buf, str_len);
    }

    /* print response */
    for (size_t i = 0; i < r.size(); i++) {
        char buf[5];
        utf32_to_utf8(buf, sizeof(buf), r[i].Code);
        printf("%s\tU+%04x\t%s\n", buf, r[i].Code, r[i].Name.c_str());
    }

    /* write shutdown request */
    ch->reset();
    ch->write_int8(0); /* 0 = shutdown */
    struct xi_channel::span out = ch->copy_output();
    ch->closing = 1;
    xi_nub_io_write(nch, out.data, out.length, xi_client_request_write_cb);
}

static void xi_client_request_write_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: write(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_func("ch=%s, len=%zu\n", xi_nub_io_get_identity(nch), len);

    if (ch->closing) {
        xi_nub_io_close(nch, xi_client_close_cb);
        return;
    }

    /* read response */
    ch->reset();
    struct xi_channel::span in = ch->copy_remaining();
    xi_nub_io_read(nch, in.data, in.length, xi_client_response_read_cb);
}

static void xi_client_connect_cb(xi_nub_ch *nch, xi_nub_error err)
{
    if (err) {
        fprintf(stderr, "%s: error: connect(): error_code=%d\n", __func__, err);
        return;
    }

    xi_channel *ch = new xi_channel{};
    xi_nub_io_set_user_data(nch, ch);

    /* prepare request */
    string request = join(unicode_search_terms, " ", 0, unicode_search_terms.size());

    /* debug print request */
    _debug_func("request: %s\n", request.c_str());

    /* write request */
    ch->reset();
    ch->write_int8(1); /* 1 = search */
    ch->write_string(request.data(), request.size());
    struct xi_channel::span out = ch->copy_output();
    xi_nub_io_write(nch, out.data, out.length, xi_client_request_write_cb);
}

static void xi_nub_client()
{
    xi_nub_ctx *ctx = xi_nub_ctx_create("Xi");

#if defined OS_WINDOWS
    SetConsoleOutputCP(CP_UTF8);
#endif

    _debug_func("profile_path = \"%s\";\n", xi_nub_ctx_get_profile_path(ctx));

    /* start client */
    const char* args[] = { "<self>", "nub-server" };
    xi_nub_agent *agent = xi_nub_agent_new(ctx, 2, args);
    const auto t1 = high_resolution_clock::now();
    xi_nub_agent_connect(agent, 1, xi_client_connect_cb);
    const auto t2 = high_resolution_clock::now();

    xi_nub_agent_destroy(agent);
    xi_nub_ctx_destroy(ctx);

    /*
     * print timings
     */
    if (timings_enabled)
    {
        auto tl = duration_cast<nanoseconds>(t2 - t1).count();
        printf("[nub-agent] search = %.fμs\n", tl / 1e3);
    }
}

/*
 * xi server
 */

struct nub_server_state
{
    subhash_map index;
    vector<unicode_data> data;
    vector<vector<string>> tokens;
};

static void xi_server_close_cb(xi_nub_ch *nch, xi_nub_error err)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: close(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_mark();

    delete ch;
}

static void xi_server_request_read_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len);

static void xi_server_response_write_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: write(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_func("ch=%s, len=%zu\n", xi_nub_io_get_identity(nch), len);

    /* issue read request for next command */
    ch->reset();
    struct xi_channel::span in = ch->copy_remaining();
    xi_nub_io_read(nch, in.data, in.length, xi_server_request_read_cb);
}

static void xi_server_request_read_cb(xi_nub_ch *nch, xi_nub_error err,
    void *buf, size_t len)
{
    xi_channel *ch = (xi_channel *)xi_nub_io_get_user_data(nch);

    if (err) {
        fprintf(stderr, "%s: error: read(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_func("ch=%s, len=%zu\n", xi_nub_io_get_identity(nch), len);

    ch->copy_input(xi_channel::span{buf, len});

    /* parse request */
    size_t str_len = 0;
    char str_buf[1024];
    int8_t cmd;
    ch->read_int8(&cmd);
    if (cmd != 1) {
        if (cmd != 0) {
            fprintf(stderr, "%s: error: unknown cmd=%d\n", __func__, cmd);
        }
        xi_nub_io_close(nch, xi_server_close_cb);
        return;
    }
    ch->read_string(str_buf, sizeof(str_buf), &str_len);
    string request(str_buf, str_len);

    /* get index */
    xi_nub_ctx *ctx = xi_nub_io_get_context(nch);
    nub_server_state *state = (nub_server_state *)xi_nub_ctx_get_user_data(ctx);
    if (state == nullptr) {
        state = new nub_server_state();
        xi_nub_ctx_set_user_data(ctx, state);

        /* create index */
        const auto t1 = high_resolution_clock::now();
        state->data = read_unicode_data();
        const auto t2 = high_resolution_clock::now();
        tokenize_data(state->data, state->tokens);
        index_rabin_karp(state->index, state->tokens);
        const auto t3 = high_resolution_clock::now();

        if (timings_enabled)
        {
            const auto t3 = high_resolution_clock::now();
            auto tl = duration_cast<nanoseconds>(t2 - t1).count();
            auto ti = duration_cast<nanoseconds>(t3 - t2).count();
            printf("[Rabin-Karp] load = %.fμs, index = %.fμs\n",
                tl / 1e3, ti / 1e3);
        }
    }

    /* perform request */
    vector<string> terms = split(request, " ");
    vector<unicode_data> r;
    const auto t1 = high_resolution_clock::now();
    if (optimized_search) {
        r = xi_search_rabin_karp(state->data, state->tokens, state->index, terms);
    } else {
        r = xi_search_brute_force(state->data, state->tokens, terms);
    }
    const auto t2 = high_resolution_clock::now();
    auto ts = duration_cast<nanoseconds>(t2 - t1).count();
    if (timings_enabled)
    {
        printf("[%s] search = %.fμs\n",
            (optimized_search ? "Rabin-Karp" : "Brute-Force"), ts / 1e3);
    }

    /* debug print request and response */
    if (_debug_enabled) {
        _debug_func("request: %s\n", request.c_str());
        for (size_t i = 0; i < r.size(); i++) {
            char buf[5];
            utf32_to_utf8(buf, sizeof(buf), r[i].Code);
            _debug_func("response: %s\tU+%04x\t%s\n", buf, r[i].Code, r[i].Name.c_str());
        }
    }

    /*
     * calculate number of results that fit response buffer.
     *
     * currently we don't support cursors or anything fancy, rather the
     * results are truncated to fit the response buffer. it would be
     * relatively easy to add a start row to the request, and methods
     * to return just the count of the results. at that point we could
     * start using sqlite with the FTS5 (full-text search) extension.
     */
    size_t nr = 0, rsz = sizeof(int64_t);
    while (nr < r.size()) {
        /* presently we calculate response size manually, but ideally
         * should be done with a serialization/deserialization library.
         *
         * <codepoint:int32> <string.length:int64> <string.data.int8>
         */
        size_t isz = sizeof(int32_t) + sizeof(int64_t) + r[nr].Name.size();
        if (rsz + isz > sizeof(ch->buf)) break;
        rsz += isz;
        nr++;
    }

    /* write response */
    ch->reset();
    ch->write_int64(nr);
    for (size_t i = 0; i < nr; i++) {
        ch->write_int32((int32_t)r[i].Code);
        ch->write_string(r[i].Name.data(), r[i].Name.size());
    }
    struct xi_channel::span out = ch->copy_output();
    xi_nub_io_write(nch, out.data, out.length, xi_server_response_write_cb);
}

static void xi_server_accept_cb(xi_nub_ch *nch, xi_nub_error err)
{
    if (err) {
        fprintf(stderr, "%s: error: accept(): error_code=%d\n", __func__, err);
        return;
    }

    _debug_mark();

    xi_channel *ch = new xi_channel{};
    xi_nub_io_set_user_data(nch, ch);

    /* read request */
    ch->reset();
    struct xi_channel::span in = ch->copy_remaining();
    xi_nub_io_read(nch, in.data, in.length, xi_server_request_read_cb);
}

static void xi_nub_server()
{
    xi_nub_ctx *ctx = xi_nub_ctx_create("Xi");

    _debug_func("profile_path = \"%s\";\n", xi_nub_ctx_get_profile_path(ctx));

    const char* args[] = { "<self>", "nub-server" };
    xi_nub_agent *agent = xi_nub_agent_new(ctx, 2, args);
    xi_nub_agent_accept(agent, 8, xi_server_accept_cb);

    xi_nub_agent_destroy(agent);
    xi_nub_ctx_destroy(ctx);
}

/*
 * stand alone client
 */

static void xi_standalone_client()
{
    if (optimized_search) {
        xi_print_results(xi_search_rabin_karp(unicode_search_terms));
    } else {
        xi_print_results(xi_search_brute_force(unicode_search_terms));
    }
}

/*
 * command line options
 */

static void print_help(int argc, char **argv)
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
        "  -d, --debug                  enable search debug\n"
        "  -t, --timings                enable search timings\n"
        "  -x, --brute-force            disable search optimization\n"
        "  -s, --stand-alone            run in stand-alone mode\n"
        "  -h, --help                   command line help\n",
        argv[0]);
}

static bool check_param(bool cond, const char *param)
{
    if (cond) {
        printf("error: %s requires parameter\n", param);
    }
    return (help_text = cond);
}

static bool match_option(const char *arg, const char *opt, const char *longopt)
{
    return strcmp(arg, opt) == 0 || strcmp(arg, longopt) == 0;
}

static bool match_command(const char *arg, const char *cmd)
{
    return strcmp(arg, cmd) == 0;
}

static bool parse_nub_server(int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "error: invalid nub-server options\n");
        return false;
    }
    return (nub_server = true);
}

static bool parse_unicode_search(int argc, char **argv)
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

static bool parse_codepint_lookup(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "error: codepoint lookup missing term\n");
        return false;
    }
    unicode_numeric_term = argv[1];
    return true;
}

static bool parse_options(int argc, char **argv)
{
    int i = 1;
    while (i < argc) {
        if (match_option(argv[i], "-u", "--unicode-data")) {
            if (check_param(++i == argc, "--unicode-data")) break;
            unicode_data_file = argv[i++];
        } else if (match_option(argv[i], "-d", "--debug")) {
            _debug_enabled = true;
            i++;
        } else if (match_option(argv[i], "-t", "--timings")) {
            timings_enabled = true;
            i++;
        } else if (match_option(argv[i], "-s", "--stand-alone")) {
            standalone_search = true;
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
    } else if (match_command(argv[i], "nub-server")) {
        return parse_nub_server(argc-i, argv+i);
    } else if (match_command(argv[i], "unicode")) {
        return parse_unicode_search(argc-i, argv+i);
    } else if (match_command(argv[i], "codepoint")) {
        return parse_codepint_lookup(argc-i, argv+i);
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
        if (standalone_search) {
            xi_standalone_client();
        } else {
            xi_nub_client();
        }
    }
    if (unicode_numeric_term.size()) {
        xi_print_results(xi_codepoint_lookup(unicode_numeric_term));
    }

    if (nub_server) {
        xi_nub_server();
    }
}
