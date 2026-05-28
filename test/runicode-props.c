#include <rlib/rlib.h>

/* Spot checks for the UCD-driven classifiers. The fanout below
 * covers the obvious script blocks plus a handful of edge cases
 * the ASCII-fast helpers didn't catch:
 *
 *   - ASCII boundary (0x7F vs 0x80) - confirms the table walk
 *     agrees with r_unichar_is_ascii_* for the low range.
 *   - Latin-1 Supplement letters (U+00E9 e-acute), digits (no
 *     dedicated digits in Latin-1, but U+00B2 / U+00B3 are No),
 *     punctuation (U+00BF inverted question mark).
 *   - Greek (U+03B1 alpha), Cyrillic (U+0410 A), Arabic (U+0627 alef),
 *     Hebrew (U+05D0 alef).
 *   - CJK (U+4E00 - first ideograph), Hiragana (U+3042 a),
 *     Katakana (U+30A2 a).
 *   - Combining marks (U+0301 acute), digits beyond ASCII
 *     (U+0660 Arabic-Indic 0).
 *   - Spaces beyond ASCII (U+00A0 NBSP, U+2028 LINE SEPARATOR,
 *     U+3000 IDEOGRAPHIC SPACE).
 *   - Symbols (U+00A9 ©, U+20AC €, U+2603 SNOWMAN).
 *   - Format chars (U+200B zero-width space - Cf, not space),
 *     surrogate halves (U+D800), private use (U+E000),
 *     non-characters (U+FDD0).
 */

RTEST (runicode_props, is_letter, RTEST_FAST)
{
  /* Letters across scripts. */
  r_assert (r_unichar_is_letter ('A'));
  r_assert (r_unichar_is_letter ('z'));
  r_assert (r_unichar_is_letter (0x00E9));    /* é */
  r_assert (r_unichar_is_letter (0x03B1));    /* α */
  r_assert (r_unichar_is_letter (0x0410));    /* CYRILLIC A */
  r_assert (r_unichar_is_letter (0x0627));    /* ARABIC ALEF */
  r_assert (r_unichar_is_letter (0x05D0));    /* HEBREW ALEF */
  r_assert (r_unichar_is_letter (0x4E00));    /* CJK first ideograph */
  r_assert (r_unichar_is_letter (0x3042));    /* HIRAGANA A */

  /* Non-letters. */
  r_assert (!r_unichar_is_letter ('0'));
  r_assert (!r_unichar_is_letter (' '));
  r_assert (!r_unichar_is_letter (0x0301));   /* combining acute - mark */
  r_assert (!r_unichar_is_letter (0x00A9));   /* © - symbol */
  r_assert (!r_unichar_is_letter (0x200B));   /* ZWSP - format */
  r_assert (!r_unichar_is_letter (0xD800));   /* surrogate */
  r_assert (!r_unichar_is_letter (0x110000)); /* out of range */
}
RTEST_END;

RTEST (runicode_props, is_digit, RTEST_FAST)
{
  /* Nd codepoints. */
  r_assert (r_unichar_is_digit ('0'));
  r_assert (r_unichar_is_digit ('9'));
  r_assert (r_unichar_is_digit (0x0660));     /* Arabic-Indic 0 */
  r_assert (r_unichar_is_digit (0x0669));     /* Arabic-Indic 9 */
  r_assert (r_unichar_is_digit (0xFF10));     /* fullwidth 0 */

  /* No (other number) and Nl (letter-number) - NOT digit per Nd. */
  r_assert (!r_unichar_is_digit (0x00B2));    /* SUPERSCRIPT TWO */
  r_assert (!r_unichar_is_digit (0x2160));    /* ROMAN NUMERAL ONE - Nl */

  /* Letters and others. */
  r_assert (!r_unichar_is_digit ('a'));
  r_assert (!r_unichar_is_digit (0x4E00));
}
RTEST_END;

RTEST (runicode_props, is_alnum, RTEST_FAST)
{
  r_assert (r_unichar_is_alnum ('a'));
  r_assert (r_unichar_is_alnum ('0'));
  r_assert (r_unichar_is_alnum (0x03B1));
  r_assert (r_unichar_is_alnum (0x4E00));
  r_assert (r_unichar_is_alnum (0x0660));

  r_assert (!r_unichar_is_alnum (' '));
  r_assert (!r_unichar_is_alnum ('!'));
  r_assert (!r_unichar_is_alnum (0x00A9));
}
RTEST_END;

RTEST (runicode_props, is_space, RTEST_FAST)
{
  /* White_Space derived property. */
  r_assert (r_unichar_is_space (' '));
  r_assert (r_unichar_is_space ('\t'));
  r_assert (r_unichar_is_space ('\n'));
  r_assert (r_unichar_is_space ('\f'));
  r_assert (r_unichar_is_space (0x0085));     /* NEL */
  r_assert (r_unichar_is_space (0x00A0));     /* NBSP */
  r_assert (r_unichar_is_space (0x2028));     /* LINE SEPARATOR */
  r_assert (r_unichar_is_space (0x2029));     /* PARAGRAPH SEPARATOR */
  r_assert (r_unichar_is_space (0x3000));     /* IDEOGRAPHIC SPACE */

  /* ZWSP (U+200B) is Cf, NOT White_Space, despite the name. */
  r_assert (!r_unichar_is_space (0x200B));
  r_assert (!r_unichar_is_space ('a'));
}
RTEST_END;

RTEST (runicode_props, is_control, RTEST_FAST)
{
  /* C0 controls. */
  r_assert (r_unichar_is_control (0x00));
  r_assert (r_unichar_is_control (0x1F));
  r_assert (r_unichar_is_control (0x7F));
  /* C1 controls. */
  r_assert (r_unichar_is_control (0x80));
  r_assert (r_unichar_is_control (0x9F));

  r_assert (!r_unichar_is_control (' '));
  r_assert (!r_unichar_is_control ('a'));
  r_assert (!r_unichar_is_control (0x200B));  /* Cf, not Cc */
}
RTEST_END;

RTEST (runicode_props, is_print, RTEST_FAST)
{
  /* Printable per Unicode Standard recommendation: NOT in
   * {Cc, Cf, Cs, Co, Cn}. Space itself counts as printable. */
  r_assert (r_unichar_is_print (' '));
  r_assert (r_unichar_is_print ('a'));
  r_assert (r_unichar_is_print (0x03B1));
  r_assert (r_unichar_is_print (0x4E00));
  r_assert (r_unichar_is_print (0x00A0));     /* NBSP - Zs */

  /* Non-printable categories. */
  r_assert (!r_unichar_is_print (0x00));      /* Cc */
  r_assert (!r_unichar_is_print (0x200B));    /* Cf */
  r_assert (!r_unichar_is_print (0xD800));    /* Cs */
  r_assert (!r_unichar_is_print (0xE000));    /* Co (private use) */
  r_assert (!r_unichar_is_print (0xFDD0));    /* Cn (non-character) */
  r_assert (!r_unichar_is_print (0x110000));  /* out of range -> Cn */
}
RTEST_END;

RTEST (runicode_props, is_punct, RTEST_FAST)
{
  /* P* categories. */
  r_assert (r_unichar_is_punct ('!'));
  r_assert (r_unichar_is_punct ('.'));
  r_assert (r_unichar_is_punct ('-'));
  r_assert (r_unichar_is_punct ('('));
  r_assert (r_unichar_is_punct (0x00BF));     /* ¿ */
  r_assert (r_unichar_is_punct (0x2014));     /* em dash */
  r_assert (r_unichar_is_punct (0x3001));     /* ideographic comma */

  /* Symbols are NOT punctuation. */
  r_assert (!r_unichar_is_punct (0x00A9));    /* © - So */
  r_assert (!r_unichar_is_punct (0x20AC));    /* € - Sc */
  r_assert (!r_unichar_is_punct ('a'));
  r_assert (!r_unichar_is_punct ('0'));
}
RTEST_END;

RTEST (runicode_props, is_mark, RTEST_FAST)
{
  /* M* categories. */
  r_assert (r_unichar_is_mark (0x0300));      /* combining grave - Mn */
  r_assert (r_unichar_is_mark (0x0301));      /* combining acute - Mn */
  r_assert (r_unichar_is_mark (0x0903));      /* devanagari sign visarga - Mc */
  r_assert (r_unichar_is_mark (0x0488));      /* cyrillic combining hundred-thousands - Me */

  r_assert (!r_unichar_is_mark ('a'));
  r_assert (!r_unichar_is_mark (' '));
}
RTEST_END;

RTEST (runicode_props, is_symbol, RTEST_FAST)
{
  /* S* categories. */
  r_assert (r_unichar_is_symbol ('+'));       /* Sm */
  r_assert (r_unichar_is_symbol ('<'));       /* Sm */
  r_assert (r_unichar_is_symbol ('$'));       /* Sc */
  r_assert (r_unichar_is_symbol (0x20AC));    /* € - Sc */
  r_assert (r_unichar_is_symbol (0x00A9));    /* © - So */
  r_assert (r_unichar_is_symbol (0x2603));    /* SNOWMAN - So */
  r_assert (r_unichar_is_symbol ('^'));       /* Sk - modifier symbol */

  r_assert (!r_unichar_is_symbol ('a'));
  r_assert (!r_unichar_is_symbol ('!'));      /* punct */
}
RTEST_END;

RTEST (runicode_props, to_upper, RTEST_FAST)
{
  /* ASCII. */
  r_assert_cmpuint (r_unichar_to_upper ('a'), ==, 'A');
  r_assert_cmpuint (r_unichar_to_upper ('z'), ==, 'Z');
  /* Already uppercase -> unchanged. */
  r_assert_cmpuint (r_unichar_to_upper ('A'), ==, 'A');
  /* Non-letters -> unchanged. */
  r_assert_cmpuint (r_unichar_to_upper ('0'), ==, '0');
  r_assert_cmpuint (r_unichar_to_upper (' '), ==, ' ');

  /* Latin-1 Supplement. */
  r_assert_cmpuint (r_unichar_to_upper (0x00E9), ==, 0x00C9);  /* é -> É */
  /* Greek. */
  r_assert_cmpuint (r_unichar_to_upper (0x03B1), ==, 0x0391);  /* α -> Α */
  /* Cyrillic. */
  r_assert_cmpuint (r_unichar_to_upper (0x0430), ==, 0x0410);  /* а -> А */
  /* Outside any cased range -> identity. */
  r_assert_cmpuint (r_unichar_to_upper (0x4E00), ==, 0x4E00);
}
RTEST_END;

RTEST (runicode_props, to_lower, RTEST_FAST)
{
  r_assert_cmpuint (r_unichar_to_lower ('A'), ==, 'a');
  r_assert_cmpuint (r_unichar_to_lower ('Z'), ==, 'z');
  r_assert_cmpuint (r_unichar_to_lower ('a'), ==, 'a');
  r_assert_cmpuint (r_unichar_to_lower ('0'), ==, '0');

  r_assert_cmpuint (r_unichar_to_lower (0x00C9), ==, 0x00E9);  /* É -> é */
  r_assert_cmpuint (r_unichar_to_lower (0x0391), ==, 0x03B1);  /* Α -> α */
  r_assert_cmpuint (r_unichar_to_lower (0x0410), ==, 0x0430);  /* А -> а */
  r_assert_cmpuint (r_unichar_to_lower (0x4E00), ==, 0x4E00);
}
RTEST_END;

RTEST (runicode_props, to_title, RTEST_FAST)
{
  /* For most cased letters, title == upper. */
  r_assert_cmpuint (r_unichar_to_title ('a'), ==, 'A');
  r_assert_cmpuint (r_unichar_to_title (0x00E9), ==, 0x00C9);

  /* The few digraph-like codepoints have a distinct titlecase
   * form (one uppercase letter followed by lowercase). U+01F1 DZ
   * titlecase is U+01F2 Dz. */
  r_assert_cmpuint (r_unichar_to_title (0x01F1), ==, 0x01F2);
  r_assert_cmpuint (r_unichar_to_title (0x01F3), ==, 0x01F2);
  /* Compare against to_upper which lifts both letters: U+01F1. */
  r_assert_cmpuint (r_unichar_to_upper (0x01F3), ==, 0x01F1);
}
RTEST_END;

RTEST (runicode_props, ascii_subset_matches_ascii_helpers, RTEST_FAST)
{
  /* For every codepoint < 0x80 the UCD-backed classifier must
   * agree with the ASCII-fast helper. This is a sanity check
   * that the table walk doesn't silently corrupt the ASCII
   * range. is_print is the most subtle case (the ASCII helper
   * excludes 0x7F, which is Cc; both reject). */
  ruint32 cp;

  for (cp = 0; cp < 0x80; cp++) {
    r_assert_cmpint (r_unichar_is_letter (cp), ==, r_unichar_is_ascii_letter (cp));
    r_assert_cmpint (r_unichar_is_digit (cp), ==, r_unichar_is_ascii_digit (cp));
    r_assert_cmpint (r_unichar_is_alnum (cp), ==, r_unichar_is_ascii_alnum (cp));
    r_assert_cmpint (r_unichar_is_space (cp), ==, r_unichar_is_ascii_space (cp));
    r_assert_cmpint (r_unichar_is_control (cp), ==, r_unichar_is_ascii_control (cp));
    r_assert_cmpint (r_unichar_is_print (cp), ==, r_unichar_is_ascii_print (cp));

    /* POSIX is_punct and UCD is_punct disagree on ASCII symbols:
     * '$' / '+' / '<' / '=' / '>' / '|' / '~' / '`' / '^' are
     * Sc / Sm / Sk in UCD, NOT P*. is_ascii_punct (POSIX) treats
     * them as punctuation. The right cross-check is therefore
     * "ASCII punct == (UCD punct OR UCD symbol)" - they cover the
     * same set of codepoints, partitioned differently. */
    r_assert_cmpint (r_unichar_is_punct (cp) || r_unichar_is_symbol (cp),
        ==, r_unichar_is_ascii_punct (cp));
  }
}
RTEST_END;

/* DerivedGeneralCategory cross-check sample. The UCD-data subdir
 * ships extracted/DerivedGeneralCategory.txt giving the official
 * General_Category for every codepoint as authoritative-vs-derived
 * cross-check. A sampled comparison guards against generator
 * regressions; the table below picks one codepoint per script
 * range plus a handful of edge cases. */

typedef struct {
  ruint32 cp;
  const rchar * name;
  rboolean expect_letter;
  rboolean expect_digit;
  rboolean expect_space;
  rboolean expect_control;
  rboolean expect_punct;
  rboolean expect_mark;
  rboolean expect_symbol;
} RUcdSample;

static const RUcdSample ucd_samples[] = {
  /* cp      name                               L  D  Sp Ctl P  M  Sy */
  {  0x0041, "LATIN CAPITAL LETTER A",          1, 0, 0, 0, 0, 0, 0 },
  {  0x0030, "DIGIT ZERO",                      0, 1, 0, 0, 0, 0, 0 },
  {  0x0020, "SPACE",                           0, 0, 1, 0, 0, 0, 0 },
  {  0x0021, "EXCLAMATION MARK",                0, 0, 0, 0, 1, 0, 0 },
  {  0x002B, "PLUS SIGN",                       0, 0, 0, 0, 0, 0, 1 },
  {  0x007F, "DELETE",                          0, 0, 0, 1, 0, 0, 0 },
  {  0x00A0, "NO-BREAK SPACE",                  0, 0, 1, 0, 0, 0, 0 },
  {  0x00A9, "COPYRIGHT SIGN",                  0, 0, 0, 0, 0, 0, 1 },
  {  0x00E9, "LATIN SMALL E WITH ACUTE",        1, 0, 0, 0, 0, 0, 0 },
  {  0x00BF, "INVERTED QUESTION MARK",          0, 0, 0, 0, 1, 0, 0 },
  {  0x0301, "COMBINING ACUTE ACCENT",          0, 0, 0, 0, 0, 1, 0 },
  {  0x03B1, "GREEK SMALL ALPHA",               1, 0, 0, 0, 0, 0, 0 },
  {  0x0410, "CYRILLIC CAPITAL A",              1, 0, 0, 0, 0, 0, 0 },
  {  0x0660, "ARABIC-INDIC DIGIT ZERO",         0, 1, 0, 0, 0, 0, 0 },
  {  0x0627, "ARABIC LETTER ALEF",              1, 0, 0, 0, 0, 0, 0 },
  {  0x2028, "LINE SEPARATOR",                  0, 0, 1, 0, 0, 0, 0 },
  {  0x2160, "ROMAN NUMERAL ONE (Nl)",          0, 0, 0, 0, 0, 0, 0 },
  {  0x20AC, "EURO SIGN",                       0, 0, 0, 0, 0, 0, 1 },
  {  0x3000, "IDEOGRAPHIC SPACE",               0, 0, 1, 0, 0, 0, 0 },
  {  0x3042, "HIRAGANA LETTER A",               1, 0, 0, 0, 0, 0, 0 },
  {  0x30A2, "KATAKANA LETTER A",               1, 0, 0, 0, 0, 0, 0 },
  {  0x4E00, "CJK UNIFIED IDEOGRAPH-4E00",      1, 0, 0, 0, 0, 0, 0 },
  {  0xD800, "FIRST HIGH SURROGATE (Cs)",       0, 0, 0, 0, 0, 0, 0 },
  {  0xE000, "PRIVATE USE FIRST",               0, 0, 0, 0, 0, 0, 0 },
  {  0xFDD0, "NON-CHARACTER (Cn)",              0, 0, 0, 0, 0, 0, 0 },
  { 0x10000, "LINEAR B SYLLABLE B008 A",        1, 0, 0, 0, 0, 0, 0 },
  { 0x1F600, "GRINNING FACE",                   0, 0, 0, 0, 0, 0, 1 },
};

RTEST_LOOP (runicode_props, ucd_sample_classifications, RTEST_FAST,
    0, R_N_ELEMENTS (ucd_samples))
{
  const RUcdSample * s = &ucd_samples[__i];
  r_assert_cmpint (r_unichar_is_letter (s->cp),  ==, s->expect_letter);
  r_assert_cmpint (r_unichar_is_digit (s->cp),   ==, s->expect_digit);
  r_assert_cmpint (r_unichar_is_space (s->cp),   ==, s->expect_space);
  r_assert_cmpint (r_unichar_is_control (s->cp), ==, s->expect_control);
  r_assert_cmpint (r_unichar_is_punct (s->cp),   ==, s->expect_punct);
  r_assert_cmpint (r_unichar_is_mark (s->cp),    ==, s->expect_mark);
  r_assert_cmpint (r_unichar_is_symbol (s->cp),  ==, s->expect_symbol);
}
RTEST_END;
