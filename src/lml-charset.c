/*****
*
* Copyright (C) 2009 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-LML program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libprelude/prelude-string.h>
#include <libprelude/prelude-log.h>

#include "lml-charset.h"

#ifdef HAVE_LIBICU
# include <unicode/ucnv.h>
# include <unicode/ucsdet.h>
#else
# include <iconv.h>
#endif

struct lml_charset {
#ifdef HAVE_LIBICU
        UConverter *from;
        UConverter *to;
#else
        iconv_t conv;
#endif
        unsigned int max_char_size;
};



#ifdef HAVE_LIBICU
static UConverter *icu_initialize_converter(const char *charset)
{
        UConverter *conv;
        UErrorCode status = U_ZERO_ERROR;

        conv = ucnv_open(charset, &status);
        if ( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: couldn't open %s converter : %s.\n", charset, u_errorName(status));
                return NULL;
        }

        return conv;
}


static int _charset_detect(const char *in, size_t len, const char **charset, int *confidence)
{
        UCharsetDetector *csd;
        const UCharsetMatch *ucm;
        UErrorCode status = U_ZERO_ERROR;

        csd = ucsdet_open(&status);
        if ( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: error opening character set detector: %s.\n", u_errorName(status));
                return -1;
        }

        ucsdet_setText(csd, in, len, &status);
        if( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: error setting text for character set detection: %s.\n", u_errorName(status));
                goto error;
        }

        ucm = ucsdet_detect(csd, &status);
        if( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: character set detection failed: %s.\n", u_errorName(status));
                goto error;
        }

        *confidence = ucsdet_getConfidence(ucm, &status);
        if ( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: error retrieving character set confidence: %s.\n", u_errorName(status));
                goto error;
        }

        *charset = ucsdet_getName(ucm, &status);
        if ( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: error retrieving character set name: %s.\n", u_errorName(status));
                goto error;
        }

        return 0;

error:
        ucsdet_close(csd);
        return -1;
}


static int _charset_convert(lml_charset_t *lc, const char *in, size_t inlen, char **out, size_t *outlen)
{
        char *target;
        size_t maxlen;
        UErrorCode status = U_ZERO_ERROR;

        maxlen = lc->max_char_size * inlen;
        if ( maxlen < inlen || maxlen + 1 < maxlen )
                return -1;

        *out = target = malloc(maxlen + 1);
        if ( ! *out ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: failed allocating %lu bytes.\n", maxlen);
                return -1;
        }

        ucnv_convertEx(lc->to, lc->from, &target, *out + maxlen, &in, in + inlen, NULL, NULL, NULL, NULL, 0, TRUE, &status);
        if ( U_FAILURE(status) ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: failed converting input to UTF-8: %s.\n", u_errorName(status));
                free(*out);
                return -1;
        }

        *outlen = target - *out;
        target[*outlen] = '\0';

        return 0;
}


static void _charset_close(lml_charset_t *lc)
{
        if ( lc->from )
                ucnv_close(lc->from);

        if ( lc->to )
                ucnv_close(lc->to);
}


static int _charset_open(lml_charset_t **lc, const char *from)
{
        *lc = calloc(1, sizeof(**lc));
        if ( ! *lc ) {
                prelude_log(PRELUDE_LOG_ERR, "ICU: memory exhausted.\n");
                return -1;
        }

        (*lc)->from = icu_initialize_converter(from);
        if ( ! (*lc)->from )
                return lml_charset_close(*lc);

        (*lc)->to = icu_initialize_converter("UTF-8");
        if ( ! (*lc)->to )
                return lml_charset_close(*lc);

        (*lc)->max_char_size = ucnv_getMaxCharSize((*lc)->to);

        return 0;
}

#else


static int _charset_convert(lml_charset_t *lc, const char *in, size_t inlen, char **out, size_t *outlen)
{
        char *outp;
        size_t ret, olen, bkpolen;

        bkpolen = olen = inlen * lc->max_char_size;

        if ( olen + 1 < olen )
                return -1;

        *out = outp = malloc(olen + 1);
        if ( ! outp )
                return -1;

        ret = iconv(lc->conv, (char **) &in, &inlen, &outp, &olen);
        if ( ret == (size_t) -1 ) {
                free(*out);
                prelude_log(PRELUDE_LOG_ERR, "ICONV: failed converting string to UTF-8: %s.\n", strerror(errno));
                return -1;
        }

        *outlen = (bkpolen - olen);
        outp[0] = '\0';

        return 0;
}


static int _charset_detect(const char *in, size_t inlen, const char **out, int *confidence)
{
        return -1;
}


static void _charset_close(lml_charset_t *lc)
{
        if ( lc->conv != (iconv_t) -1 )
                iconv_close(lc->conv);
}


static int _charset_open(lml_charset_t **lc, const char *from)
{
        *lc = calloc(1, sizeof(**lc));
        if ( ! *lc ) {
                prelude_log(PRELUDE_LOG_ERR, "ICONV: memory exhausted.\n");
                return -1;
        }

        (*lc)->conv = iconv_open("UTF-8", from);
        if ( (*lc)->conv == (iconv_t) -1 ) {
                prelude_log(PRELUDE_LOG_ERR, "ICONV: couldn't open %s -> UTF-8 converter : %s.\n", from, strerror(errno));
                free(*lc);
                return -1;
        }

        (*lc)->max_char_size = 4; /* Warning: this is UTF-8 specific */

        return 0;
}
#endif


int lml_charset_convert(lml_charset_t *lc, const char *in, size_t inlen, char **out, size_t *outlen)
{
        return _charset_convert(lc, in, inlen, out, outlen);
}


int lml_charset_detect(const char *in, size_t inlen, const char **out, int *confidence)
{
        return _charset_detect(in, inlen, out, confidence);
}


int lml_charset_close(lml_charset_t *lc)
{
        _charset_close(lc);
        free(lc);
        return 0;
}


int lml_charset_open(lml_charset_t **lc, const char *from)
{
        return _charset_open(lc, from);
}
