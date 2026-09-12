package version

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Pair is one comparison from the corpus.
type Pair struct {
	Kind     string
	A, B     string
	Expected int
	Line     int
}

// Corpus reads the file of comparisons shared by the unit test and the
// integration test.
func Corpus(t *testing.T, path string) []Pair {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("corpus: %v", err)
	}
	defer file.Close()

	var pairs []Pair
	scanner := bufio.NewScanner(file)
	number := 0
	for scanner.Scan() {
		number++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("corpus, line %d: %d columns", number, len(fields))
		}
		expected, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatalf("corpus, line %d: %v", number, err)
		}
		pairs = append(pairs, Pair{
			Kind: fields[0], A: fields[1], B: fields[2], Expected: expected, Line: number,
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if len(pairs) == 0 {
		t.Fatal("the corpus is empty")
	}
	return pairs
}

// Sign reduces the result of a comparison to -1, 0 or 1.
func Sign(result int) int {
	switch {
	case result < 0:
		return -1
	case result > 0:
		return 1
	}
	return 0
}

func TestVersionComparisonCorpus(t *testing.T) {
	for _, pair := range Corpus(t, "testdata/corpus.tsv") {
		var result int
		switch pair.Kind {
		case "deb":
			result = Sign(CompareDeb(pair.A, pair.B))
		case "rpm":
			result = Sign(CompareRPM(pair.A, pair.B))
		default:
			t.Fatalf("line %d: unknown kind %q", pair.Line, pair.Kind)
		}
		if result != pair.Expected {
			t.Errorf("line %d: %s %q ? %q = %d, expected %d",
				pair.Line, pair.Kind, pair.A, pair.B, result, pair.Expected)
		}
		// The comparison has to be antisymmetric: otherwise the same pair of
		// versions gives different answers depending on the order of the
		// arguments.
		var reversed int
		if pair.Kind == "deb" {
			reversed = Sign(CompareDeb(pair.B, pair.A))
		} else {
			reversed = Sign(CompareRPM(pair.B, pair.A))
		}
		if reversed != -pair.Expected {
			t.Errorf("line %d: the comparison is not antisymmetric (%d against %d)",
				pair.Line, result, reversed)
		}
	}
}

func TestComparisonIsTransitive(t *testing.T) {
	// An ordered sequence of versions: each next one has to be newer than
	// every previous one. This catches errors the pairs alone do not show.
	sequences := map[string][]string{
		// "1.0a" stands after "1.0-2" not by mistake: the upstream part is
		// compared before the revision, so "1.0a" is newer than every
		// "1.0-N".
		"deb": {"1.0~~", "1.0~rc1", "1.0", "1.0-1", "1.0-2", "1.0a", "1.0+deb12u1-1", "1:0.9", "2:0.1"},
		"rpm": {"1.0~rc1-1", "1.0-1", "1.0-2", "1.0^20260101-1", "1.1-1", "1:0.9-1", "2:0.1-1"},
	}
	for kind, sequence := range sequences {
		for i := 0; i < len(sequence); i++ {
			for j := i + 1; j < len(sequence); j++ {
				var result int
				if kind == "deb" {
					result = Sign(CompareDeb(sequence[i], sequence[j]))
				} else {
					result = Sign(CompareRPM(sequence[i], sequence[j]))
				}
				if result != -1 {
					t.Errorf("%s: %q should be older than %q, result %d",
						kind, sequence[i], sequence[j], result)
				}
			}
		}
	}
}
