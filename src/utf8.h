/*
 * utf8 character encoding conversion and length functions
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

#pragma once

#include <cstddef>
#include <cstdint>

namespace utf_private {
    enum {
        m = 0x3f, n = 0x1f, o = 0xf, p = 0x7,
        q = 0xc0, r = 0xe0, t = 0xf0, u = 0xf8, v = 0x80,
        p2 = 0b11, p3 = 0b111, p4 = 0b1111, p5 = 0b11111, p6 = 0b111111
    };
}

static inline size_t utf8_codelen(const char* s)
{
    using namespace utf_private;

    if (!s) {
        return 0;
    } else if ((s[0]&v) == v) {
        return 1;
    } else if ((s[0]&u) == u) {
        return 5;
    } else if ((s[0]&t) == t) {
        return 4;
    } else if ((s[0]&r) == r) {
        return 3;
    } else if ((s[0]&q) == q) {
        return 2;
    } else {
        return 1;
    }
}

static inline size_t utf8_strlen(const char *s)
{
    using namespace utf_private;

    size_t count = 0;
    while (*s) {
        size_t c = *s;
        s++;
        if ((c&q) == q) {
            s++;
            if ((c&r) == r) {
                s++;
                if ((c&t) == t) {
                    s++;
                    if ((c&u) == u) {
                       s++;
                    }
                }
            }
        }
        count++;
    }
    return count;
}

static inline uint32_t utf8_to_utf32(const char *s)
{
    using namespace utf_private;

    if (!s) {
        return -1;
    } else if ((s[0]&v) == 0x0) {
        return s[0];
    } else if ((s[0]&u) == u) {
        return ((s[0]&p)<<24)|((s[1]&m)<<18)|((s[2]&m)<<12)|((s[3]&m)<<6)|(s[4]&m);
    } else if ((s[0]&t) == t) {
        return ((s[0]&o)<<18)|((s[1]&m)<<12)|((s[2]&m)<<6)|(s[3]&m);
    } else if ((s[0]&r) == r) {
        return ((s[0]&n)<<12)|((s[1]&m)<<6)|(s[2]&m);
    } else if ((s[0]&q) == q) {
        return ((s[0]&m)<<6)|(s[1]&m);
    } else {
        return -1;
    }
}

static inline size_t utf32_to_utf8(char *s, size_t len, uint32_t c)
{
    using namespace utf_private;

    if (c < 0x80 && len >= 2) {
        uint8_t x[2] = { uint8_t(c), 0 };
        memcpy(s, x, 2);
        return 1;
    } else if (c < 0x800 && len >= 3) {
        uint8_t x[3] = { uint8_t(q|((c>>6)&p5)), uint8_t(v|(c&p6)), 0 };
        memcpy(s, x, 3);
        return 2;
    } else if (c < 0x10000 && len >= 4) {
        uint8_t x[4] = { uint8_t(r|((c>>12)&p4)), uint8_t(v|((c>>6)&p6)),
                         uint8_t(v|(c&p6)), 0 };
        memcpy(s, x, 4);
        return 3;
    } else if (c < 0x110000 && len >= 5) {
        uint8_t x[5] = { uint8_t(t|((c>>18)&p3)), uint8_t(v|((c>>12)&p6)),
                         uint8_t(v|((c>>6)&p6)),  uint8_t(v|(c&p6)), 0 };
        memcpy(s, x, 5);
        return 4;
   } else if (c < 0x110000 && len >= 6) {
        uint8_t x[6] = { uint8_t(u|((c>>24)&p2)), uint8_t(v|((c>>18)&p6)),
                         uint8_t(v|((c>>12)&p6)), uint8_t(v|((c>>6)&p6)),
                         uint8_t(v|(c&p6)), 0 };
        memcpy(s, x, 6);
        return 5;
    }
    return -1;
}
