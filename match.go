package smb1

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrBadPattern indicates a pattern was malformed.
var ErrBadPattern = errors.New("syntax error in pattern")

// Match reports whether name matches the shell file name pattern.
// The pattern syntax is:
//
//	pattern:
//		{ term }
//	term:
//		'*'         matches any sequence of non-Separator characters
//		'?'         matches any single non-Separator character
//		'[' [ '^' ] { character-range } ']'
//		            character class (must be non-empty)
//		c           matches character c (c != '*', '?', '[')
//
//	character-range:
//		c           matches character c (c != '-', ']')
//		lo '-' hi   matches character c for lo <= c <= hi
//
// The separator is the SMB path separator '\'. When NORMALIZE_PATH is
// enabled, '/' in the pattern reads as '\' and leading ".\" elements are
// dropped; the name is never rewritten.
//
// Match requires pattern to match all of name, not just a substring.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
func Match(pattern, name string) (matched bool, err error) {
	pattern = normPattern(pattern)

chunks:
	for len(pattern) > 0 {
		var star bool
		var chunk string
		star, chunk, pattern = splitChunk(pattern)
		if star && chunk == "" {
			// The pattern ends in '*': it swallows whatever remains of the
			// name, except that '*' never crosses a path separator.
			return !strings.ContainsRune(name, PathSeparator), nil
		}

		rest, ok, err := matchChunk(chunk, name)
		// The chunk only counts as consumed if the rest of the name remains
		// matchable: when this is the final chunk, nothing may be left over.
		if ok && (len(rest) == 0 || len(pattern) > 0) {
			name = rest
			continue
		}
		if err != nil {
			return false, err
		}
		if star {
			// '*' absorbs any run of non-separator characters: retry the
			// chunk at each later position within the current path element.
			for i := 0; i < len(name) && name[i] != PathSeparator; i++ {
				rest, ok, err := matchChunk(chunk, name[i+1:])
				if ok {
					if len(pattern) == 0 && len(rest) > 0 {
						continue
					}
					name = rest
					continue chunks
				}
				if err != nil {
					return false, err
				}
			}
		}
		return false, nil
	}
	return len(name) == 0, nil
}

// splitChunk splits pattern into a leading run of '*' wildcards (reported as
// star), the fixed segment that follows, and the unconsumed remainder. The
// fixed segment extends to the next '*' that is not inside a character class.
func splitChunk(pattern string) (star bool, chunk, rest string) {
	for len(pattern) > 0 && pattern[0] == '*' {
		star = true
		pattern = pattern[1:]
	}

	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '*':
			if !inClass {
				return star, pattern[:i], pattern[i:]
			}
		}
	}
	return star, pattern, ""
}

// matchChunk matches the fixed segment chunk against a prefix of s and
// reports what is left of s. After a mismatch it keeps parsing the segment:
// a malformed pattern must be reported even when the name has already failed
// to match, so long as matching reached the malformed part.
func matchChunk(chunk, s string) (rest string, ok bool, err error) {
	failed := false
	for len(chunk) > 0 {
		if !failed && len(s) == 0 {
			failed = true
		}
		switch chunk[0] {
		case '[':
			var r rune
			if !failed {
				var width int
				r, width = utf8.DecodeRuneInString(s)
				s = s[width:]
			}
			chunk = chunk[1:]
			negated := len(chunk) > 0 && chunk[0] == '^'
			if negated {
				chunk = chunk[1:]
			}
			inRange := false
			nranges := 0
			for {
				if len(chunk) > 0 && chunk[0] == ']' && nranges > 0 {
					chunk = chunk[1:]
					break
				}
				var lo, hi rune
				if lo, chunk, err = classRune(chunk); err != nil {
					return "", false, err
				}
				hi = lo
				// classRune never returns an empty remainder, so indexing
				// chunk[0] here is safe.
				if chunk[0] == '-' {
					if hi, chunk, err = classRune(chunk[1:]); err != nil {
						return "", false, err
					}
				}
				if lo <= r && r <= hi {
					inRange = true
				}
				nranges++
			}
			if inRange == negated {
				failed = true
			}

		case '?':
			if !failed {
				if s[0] == PathSeparator {
					failed = true
				}
				_, width := utf8.DecodeRuneInString(s)
				s = s[width:]
			}
			chunk = chunk[1:]

		default:
			if !failed {
				if chunk[0] != s[0] {
					failed = true
				}
				s = s[1:]
			}
			chunk = chunk[1:]
		}
	}
	if failed {
		return "", false, nil
	}
	return s, true, nil
}

// classRune consumes one rune of a character class. The rune may not be a
// bare '-' bound or a class terminator, must be valid UTF-8, and may not end
// the pattern (the class still needs at least its closing ']'); any of those
// is a malformed pattern.
func classRune(chunk string) (r rune, rest string, err error) {
	if len(chunk) == 0 || chunk[0] == '-' || chunk[0] == ']' {
		return 0, "", ErrBadPattern
	}
	r, width := utf8.DecodeRuneInString(chunk)
	if r == utf8.RuneError && width == 1 {
		return 0, "", ErrBadPattern
	}
	rest = chunk[width:]
	if rest == "" {
		return 0, "", ErrBadPattern
	}
	return r, rest, nil
}

// normPattern applies the same separator normalization to a pattern that
// normalizePath applies to a path: with NORMALIZE_PATH enabled, forward
// slashes become backslashes and leading ".\" elements are dropped. With it
// disabled the pattern passes through untouched, and '/' is an ordinary
// character.
func normPattern(pattern string) string {
	if !NORMALIZE_PATH {
		return pattern
	}
	pattern = strings.ReplaceAll(pattern, "/", "\\")
	for strings.HasPrefix(pattern, ".\\") {
		pattern = pattern[2:]
	}
	return pattern
}

// hasGlobMeta reports whether path contains any character with special
// meaning to Match.
func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}
