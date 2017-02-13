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
        if (start + token->chunk.size > cur)
          return FALSE;
        cur -= token->chunk.size;
        token->chunk.str = (rchar *)cur;
        break;
      case R_STR_TOKEN_WILDCARD:
        if (i == first) {
          token->chunk.str = (rchar *)start;
          token->chunk.size = cur - start;
        } else {
          token->chunk.str = (rchar *)cur;
          token->chunk.size = 0;
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

    token->chunk.str = (rchar *)cur;
    switch (token->type) {
      case R_STR_TOKEN_WILDCARD_SIZED:
        if (cur + token->chunk.size > end)
          return FALSE;
        cur += token->chunk.size;
        ret = TRUE;
        break;
      case R_STR_TOKEN_WILDCARD:
        if (i + 1 == last) {
          token->chunk.size = end - cur;
        } else {
          token->chunk.size = 0;
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
    if (start + result->token[first].chunk.size > end)
      return FALSE;
    result->token[first].chunk.str = (rchar *)start;
    start += result->token[first].chunk.size;
    first++;
  }

  while (first < last && result->token[last - 1].type == R_STR_TOKEN_WILDCARD_SIZED) {
    last--;
    if (end - result->token[last].chunk.size < start)
      return FALSE;
    end -= result->token[last].chunk.size;
    result->token[last].chunk.str = (rchar *)end;
  }

  if (first < last) {
    if ((idx = r_str_match_result_next_token (result, R_STR_TOKEN_WILDCARD_SIZED, first)) < last) {
      while (first < last && result->token[first].type == R_STR_TOKEN_WILDCARD) {
        result->token[first].chunk.str = (rchar *)start;
        result->token[first].chunk.size = 0;
        first++;
      }
      while (first < last && result->token[last - 1].type == R_STR_TOKEN_WILDCARD) {
        last--;
        result->token[last].chunk.str = (rchar *)end;
        result->token[last].chunk.size = 0;
      }

      goto restart;
    } else {
      rsize i, dsize = (end - start) / (last - first);

      for (i = first; i < last; i++) {
        result->token[i].chunk.str = (rchar *)start + (i - first) * dsize;
        result->token[i].chunk.size = dsize;
      }
      result->token[i - 1].chunk.size = end - (const rchar *)result->token[i - 1].chunk.str;
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
  rchar * ptr, * match = r_alloca (token->chunk.size);
  const rchar * pattern = token->pattern;
  rsize i;

  for (i = 0, ptr = match; i < token->chunk.size; i++) {
    if (pattern[0] == '\\') pattern++;
    *ptr++ = *pattern++;
  }

  return r_str_ptr_of_str (str, size, match, token->chunk.size);
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
      t->pattern = pattern;
      t->chunk.str = NULL;
      t->type = r_str_match_pattern_next_token (pattern, &t->chunk.size, &pattern);
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

        (*result)->token[first].chunk.str = ptr;
        wrkstr = ptr + 1;
        wsize = size - (wrkstr - (const rchar *)str);

        if (first == 0) {
          if (ptr != str)
            goto beach;
        } else if (!r_str_match_wild_fill (*result, 0, first, str, ptr)) {
          continue;
        }

        ptr += (*result)->token[first].chunk.size;
        cur = first + 1;
        while ((next = r_str_match_result_next_token (*result, R_STR_TOKEN_CHARS, cur)) < tokens) {
          while (TRUE) {
            rchar * nptr;
            if ((nptr = r_str_match_token_bytes (ptr, wsize - (ptr - wrkstr), &(*result)->token[next])) == NULL)
              goto beach;

            (*result)->token[next].chunk.str = nptr;
            if (r_str_match_wild_fill (*result, cur, next, ptr, nptr)) {
              ptr = nptr + (*result)->token[next].chunk.size;
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
      (*result)->ptr = (*result)->token[0].chunk.str;
      (*result)->end = (*result)->token[tokens-1].chunk.str +
          (*result)->token[tokens-1].chunk.size;
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

