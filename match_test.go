package smb1

import (
	"errors"
	"testing"
)

// matchTests pins the pattern language: '*' and '?' never cross the '\'
// separator, character classes use '^' for negation (go-smb2 convention, not
// path.Match's '!'), and malformed patterns report ErrBadPattern. Error cases
// only report ErrBadPattern when matching actually reaches the malformed
// chunk; that boundary is pinned explicitly below.
var matchTests = []struct {
	pattern string
	name    string
	match   bool
	err     error
}{
	// Literals and empty inputs.
	{"abc", "abc", true, nil},
	{"abc", "abd", false, nil},
	{"abc", "ab", false, nil},
	{"", "", true, nil},
	{"", "abc", false, nil},
	{"abc", "", false, nil},

	// '*' matches runs of non-separator characters.
	{"*", "abc", true, nil},
	{"*c", "abc", true, nil},
	{"a*", "a", true, nil},
	{"a*", "abc", true, nil},
	{"a*", `ab\c`, false, nil},
	{"*", `a\b`, false, nil},
	{`a*\b`, `abc\b`, true, nil},
	{`a*\b`, `a\c\b`, false, nil},
	{`a*b*c*d*e*\f`, `axbxcxdxe\f`, true, nil},
	{`a*b*c*d*e*\f`, `axbxcxdxexxx\f`, true, nil},
	{`a*b*c*d*e*\f`, `axbxcxdxe\xxx\f`, false, nil},
	{`a*b*c*d*e*\f`, `axbxcxdxexxx\fff`, false, nil},
	{"*x", "xxx", true, nil},
	{"a*b?c*x", "abxbbxdbxebxczzx", true, nil},
	{"a*b?c*x", "abxbbxdbxebxczzy", false, nil},

	// '?' matches exactly one non-separator rune.
	{"a?c", "abc", true, nil},
	{"a?b", `a\b`, false, nil},
	{"a?b", "a☺b", true, nil},
	{"a???b", "a☺b", false, nil},

	// Character classes, '^'-negated classes, and ranges.
	{"ab[c]", "abc", true, nil},
	{"ab[b-d]", "abc", true, nil},
	{"ab[e-g]", "abc", false, nil},
	{"ab[^c]", "abc", false, nil},
	{"ab[^b-d]", "abc", false, nil},
	{"ab[^e-g]", "abc", true, nil},
	{"a[^a]b", "a☺b", true, nil},
	{"a[^a][^a][^a]b", "a☺b", false, nil},
	{"[a-ζ]*", "α", true, nil},
	{"*[a-ζ]", "A", false, nil},

	// Slash normalization: '/' in the pattern reads as '\', and leading ".\"
	// elements are dropped (NORMALIZE_PATH is true by default).
	{"a/*", `a\b`, true, nil},
	{"*/b", `a\b`, true, nil},
	{`.\a*`, "ab", true, nil},
	{"./a*", "ab", true, nil},

	// Malformed patterns.
	{"[", "a", false, ErrBadPattern},
	{"[^", "a", false, ErrBadPattern},
	{"[^bc", "a", false, ErrBadPattern},
	{"[]a]", "]", false, ErrBadPattern},
	{"[-]", "-", false, ErrBadPattern},
	{"[x-]", "x", false, ErrBadPattern},
	{"[x-]", "z", false, ErrBadPattern},
	{"[-x]", "a", false, ErrBadPattern},
	{"[a-b-c]", "a", false, ErrBadPattern},
	{"a[", "a", false, ErrBadPattern},
	{"a[", "ab", false, ErrBadPattern},
	{"[\xff]", "x", false, ErrBadPattern},

	// A malformed chunk that matching never reaches is not reported; the
	// pattern fails on the first chunk before the bad class is parsed.
	{"a*b[", "zzz", false, nil},
}

func TestMatch(t *testing.T) {
	for _, tt := range matchTests {
		matched, err := Match(tt.pattern, tt.name)
		if matched != tt.match || !errors.Is(err, tt.err) {
			t.Errorf("Match(%#q, %#q) = %v, %v; want %v, %v", tt.pattern, tt.name, matched, err, tt.match, tt.err)
		}
	}
}

// With NORMALIZE_PATH disabled, patterns pass through untouched: '/' is a
// literal character, not an alternate separator spelling.
func TestMatchNormalizePathDisabled(t *testing.T) {
	NORMALIZE_PATH = false
	defer func() { NORMALIZE_PATH = true }()

	tests := []struct {
		pattern string
		name    string
		match   bool
	}{
		{"a/*", `a\b`, false},
		{"a/b", "a/b", true},
		{`.\a*`, "ab", false},
		{`a\*`, `a\b`, true},
	}
	for _, tt := range tests {
		matched, err := Match(tt.pattern, tt.name)
		if err != nil {
			t.Errorf("Match(%#q, %#q) unexpected error: %v", tt.pattern, tt.name, err)
			continue
		}
		if matched != tt.match {
			t.Errorf("Match(%#q, %#q) = %v, want %v", tt.pattern, tt.name, matched, tt.match)
		}
	}
}

func TestIsPathSeparator(t *testing.T) {
	if !IsPathSeparator('\\') {
		t.Error(`IsPathSeparator('\\') = false, want true`)
	}
	if IsPathSeparator('/') {
		t.Error(`IsPathSeparator('/') = true, want false`)
	}
	if PathSeparator != '\\' {
		t.Errorf(`PathSeparator = %q, want '\\'`, PathSeparator)
	}
}
