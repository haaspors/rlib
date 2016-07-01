/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/rstr.h>

#include <string.h>

rboolean
r_str_match_simple_pattern (const rchar * str, rssize size,
    const rchar * pattern)
{
  rboolean ret;
  RStrMatchResult * res = NULL;

  ret = r_str_match_pattern (str, size, pattern, &res) == R_STR_MATCH_RESULT_OK;

  r_free (res);
  return ret;
}

static rsize
r_str_match_result_next_token (RStrMatchResult * result, RStrTokenType type, rsize i)
{
  for (; i < result->tokens; i++) {
    if (result->token[i].type == type)
      break;
  }

  return i;
}

#if 0
static rboolean
r_str_match_wild_backward (RStrMatchResult * result, rsize first, rsize idx,
    const rchar * start, const rchar * cur)
{
  rsize i;
  for (i = idx; i > first; ) {
    RStrMatchToken * token = &result->token[--i];

    switch (token->type) {
      case R_STR_TOKEN_WILDCARD_SIZED:
        if (start + token->size > cur)
          return FALSE;
        cur -= token->size;
        token->ptr_data = (rchar *)cur;
        break;
      case R_STR_TOKEN_WILDCARD:
        if (i == first) {
          token->ptr_data = (rchar *)start;
          token->size = cur - start;
        } else {
          token->ptr_data = (rchar *)cur;
          token->size = 0;
        }
        break;
      default:
        return FALSE;
    }
  }

  return TRUE;
}

static rboolean
r_str_match_wild_forward (RStrMatchResult * result, rsize first, rsize last,
    const rchar * cur, const rchar * end)
{
  rboolean ret = FALSE;
  rsize i;

  for (i = first; i < last; i++) {
    RStrMatchToken * token = &result->token[i];

    token->ptr_data = (rchar *)cur;
    switch (token->type) {
      case R_STR_TOKEN_WILDCARD_SIZED:
        if (cur + token->size > end)
          return FALSE;
        cur += token->size;
        ret = TRUE;
        break;
      case R_STR_TOKEN_WILDCARD:
        if (i + 1 == last) {
          token->size = end - cur;
        } else {
          token->size = 0;
        }
        break;
      default:
        return FALSE;
    }
  }

  return ret;
}
#endif

static rboolean
r_str_match_wild_fill (RStrMatchResult * result, rsize first, rsize last,
    const rchar * start, const rchar * end)
{
  rsize idx;

restart:
  while (first < last && result->token[first].type == R_STR_TOKEN_WILDCARD_SIZED) {
    if (start + result->token[first].size > end)
      return FALSE;
    result->token[first].ptr_data = (rchar *)start;
    start += result->token[first].size;
    first++;
  }

  while (first < last && result->token[last - 1].type == R_STR_TOKEN_WILDCARD_SIZED) {
    last--;
    if (end - result->token[last].size < start)
      return FALSE;
    end -= result->token[last].size;
    result->token[last].ptr_data = (rchar *)end;
  }

  if (first < last) {
    if ((idx = r_str_match_result_next_token (result, R_STR_TOKEN_WILDCARD_SIZED, first)) < last) {
      while (first < last && result->token[first].type == R_STR_TOKEN_WILDCARD) {
        result->token[first].ptr_data = (rchar *)start;
        result->token[first].size = 0;
        first++;
      }
      while (first < last && result->token[last - 1].type == R_STR_TOKEN_WILDCARD) {
        last--;
        result->token[last].ptr_data = (rchar *)end;
        result->token[last].size = 0;
      }

      goto restart;
    } else {
      rsize i, dsize = (end - start) / (last - first);

      for (i = first; i < last; i++) {
        result->token[i].ptr_data = (rchar *)start + (i - first) * dsize;
        result->token[i].size = dsize;
      }
      result->token[i - 1].size = end - (const rchar *)result->token[i - 1].ptr_data;
    }
  }

  return TRUE;
}

static RStrTokenType
r_str_match_pattern_next_token (const rchar * pattern,
    rsize * chars, const rchar ** end)
{
  RStrTokenType ret;

  *chars = 0;

  if (*pattern == 0) {
    ret = R_STR_TOKEN_NONE;
  } else if (*pattern == '*') {
    do {
      pattern++;
    } while (pattern[0] == '*');

    ret = R_STR_TOKEN_WILDCARD;
  } else if (pattern[0] == '?') {
    do {
      pattern++;
      (*chars)++;
    } while (pattern[0] == '?');

    ret = R_STR_TOKEN_WILDCARD_SIZED;
  } else {
    rsize s;

    ret = R_STR_TOKEN_NONE;

    do {
      if ((s = strcspn (pattern, "*?\\")) > 0) {
        ret = R_STR_TOKEN_CHARS;
        pattern += s;
        *chars += s;
      }

      if (pattern[0] == '*' || pattern[0] == '?') {
        break;
      } else if (pattern[0] == '\\') {
        if (pattern[1] != 0) {
          pattern += 2;
          (*chars)++;
          ret = R_STR_TOKEN_CHARS;
        } else {
          ret = R_STR_TOKEN_NONE;
          break;
        }
      }
    } while (pattern[0] != 0);
  }

  *end = pattern;
  return ret;
}

static rsize
r_str_match_validate_pattern (const rchar * pattern)
{
  rsize ret = 0;
  rsize chars;

  while (r_str_match_pattern_next_token (pattern, &chars, &pattern) != R_STR_TOKEN_NONE)
    ret++;
  if (*pattern != 0)
    ret = 0;

  return ret;
}

static rchar *
r_str_match_token_bytes (const rchar * str, rsize size, const RStrMatchToken * token)
{
  rchar * ptr, * match = r_alloca (token->size);
  const rchar * pattern = token->ptr_pattern;
  rsize i;

  for (i = 0, ptr = match; i < token->size; i++) {
    if (pattern[0] == '\\') pattern++;
    *ptr++ = *pattern++;
  }
  *ptr = 0;

  return r_strnstr (str, match, size);
}

RStrMatchResultType
r_str_match_pattern (const rchar * str, rssize size,
    const rchar * pattern, RStrMatchResult ** result)
{
  RStrMatchResultType ret;
  rsize tokens, msize;

  if (R_UNLIKELY (str == NULL)) return R_STR_MATCH_RESULT_INVAL;
  if (R_UNLIKELY (pattern == NULL)) return R_STR_MATCH_RESULT_INVAL;
  if (R_UNLIKELY (result == NULL)) return R_STR_MATCH_RESULT_INVAL;

  if (size < 0)
    size = strlen (str);

  if (R_UNLIKELY ((tokens = r_str_match_validate_pattern (pattern)) == 0))
    return R_STR_MATCH_RESULT_INVALID_PATTERN;

  msize = sizeof (RStrMatchResult) + tokens * sizeof (RStrMatchToken);
  if (R_LIKELY ((*result = r_malloc (msize)) != NULL)) {
    RStrMatchToken * t;
    rsize first, i;

    (*result)->tokens = tokens;

    /* Setup tokens based on pattern */
    for (i = 0; i < tokens && *pattern != 0; i++) {
      t = &(*result)->token[i];
      t->ptr_pattern = pattern;
      t->ptr_data = NULL;
      t->type = r_str_match_pattern_next_token (pattern, &t->size, &pattern);
    }

    if ((first = r_str_match_result_next_token (*result, R_STR_TOKEN_CHARS, 0)) < tokens) {
      const rchar * wrkstr = str;
      rsize wsize = size;

      ret = R_STR_MATCH_RESULT_NO_MATCH;
      do {
        rchar * ptr;
        rsize cur, next;

        if ((ptr = r_str_match_token_bytes (wrkstr, wsize, &(*result)->token[first])) == NULL)
          goto beach;

        (*result)->token[first].ptr_data = ptr;
        wrkstr = ptr + 1;
        wsize = size - (wrkstr - (const rchar *)str);

        if (first == 0) {
          if (ptr != str)
            goto beach;
        } else if (!r_str_match_wild_fill (*result, 0, first, str, ptr)) {
          continue;
        }

        ptr += (*result)->token[first].size;
        cur = first + 1;
        while ((next = r_str_match_result_next_token (*result, R_STR_TOKEN_CHARS, cur)) < tokens) {
          while (TRUE) {
            rchar * nptr;
            if ((nptr = r_str_match_token_bytes (ptr, wsize - (ptr - wrkstr), &(*result)->token[next])) == NULL)
              goto beach;

            (*result)->token[next].ptr_data = nptr;
            if (r_str_match_wild_fill (*result, cur, next, ptr, nptr)) {
              ptr = nptr + (*result)->token[next].size;
              break;
            }

            ptr = nptr + 1;
          }
          cur = next + 1;
        }

        if (cur >= tokens) {
          if (ptr == wrkstr + wsize)
            ret = R_STR_MATCH_RESULT_OK;
        } else if (r_str_match_wild_fill (*result, cur, tokens, ptr, wrkstr + wsize)) {
          ret = R_STR_MATCH_RESULT_OK;
        }
      } while (first > 0 && wsize > 0 && ret == R_STR_MATCH_RESULT_NO_MATCH);
    } else {
      if (r_str_match_wild_fill (*result, 0, tokens, str, str + size))
        ret = R_STR_MATCH_RESULT_OK;
      else
        ret = R_STR_MATCH_RESULT_NO_MATCH;
    }

    if (ret == R_STR_MATCH_RESULT_OK) {
      (*result)->ptr = (*result)->token[0].ptr_data;
      (*result)->end = (*result)->token[tokens-1].ptr_data +
          (*result)->token[tokens-1].size;
    } else {
      r_free (*result);
      *result = NULL;
    }
  } else {
    ret = R_STR_MATCH_RESULT_OOM;
  }

beach:
  return ret;
}

