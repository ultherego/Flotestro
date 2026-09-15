package packages

import (
	"strconv"
	"testing"
)

// FuzzParseHumanSize feeds the size reader what dnf and pacman print for
// people.
//
// A size that is accepted is what the helper compares with the free space
// before it writes the first byte, so an accepted size must be a real
// number: printed as bytes and read again it is the same number (up to the
// precision a float carries, which is where the parser gets it from).
func FuzzParseHumanSize(f *testing.F) {
	for _, seed := range []string{
		"12 M", "1.2 GiB", "345 k", "512 B", "12M", "3.2 M", "45 MiB", "0", "", "M",
		"12 M extra", "-1 k", "1e400 k", "1.5", "9007199254740993 B",
		// These passed strconv as numbers and came out as sizes that were
		// neither refused nor real.
		"inf M", "nan k", "+Inf", "1e300 T", "18446744073709551615 B", "18446744073709551616 B",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		size, ok := ParseHumanSize(text)
		if !ok {
			if size != 0 {
				t.Fatalf("%q: refused with the size %d", text, size)
			}
			return
		}
		if size >= 1<<53 {
			// Beyond the mantissa of a float the bytes are an approximation
			// either way and are not read back.
			return
		}
		again, ok := ParseHumanSize(strconv.FormatUint(size, 10) + " B")
		if !ok || again != size {
			t.Fatalf("%q read as %d bytes, which reads back as %d, %v", text, size, again, ok)
		}
	})
}

// FuzzParseDNFTransactionSizes feeds the transaction summary reader any
// text, the way a new dnf may word it.
//
// The reader picks the lines it knows and passes over the rest; the
// property is that an unknown number is unknown - a size that is not
// marked known is zero - and that the reader never stops on the text.
func FuzzParseDNFTransactionSizes(f *testing.F) {
	for _, seed := range []string{
		"Transaction Summary\n===\nInstall  2 Packages\n\nTotal download size: 12 M\nInstalled size: 40 M\nOperation aborted.\n",
		"Upgrade  3 Packages\n\nTotal download size: 145 M\nOperation aborted.\n",
		"Install  1 Package\n\nTotal size: 3.2 M\nInstalled size: 9.1 M\n",
		"Transaction Summary:\n Upgrading:         3 packages\n\nTotal size of inbound packages is 12 MiB. Need to download 12 MiB.\nAfter this operation, 3 MiB extra will be used (install 45 MiB, remove 42 MiB).\nOperation aborted.\n",
		"Nothing to do.\n",
		"Need to download \n(install \n(install )\n(install ,\nTotal download size:\nInstalled size: inf M\n",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, output string) {
		sizes := ParseDNFTransactionSizes(output)
		if !sizes.DownloadKnown && sizes.Download != 0 {
			t.Fatalf("%q: the download is unknown yet %d", output, sizes.Download)
		}
		if !sizes.InstallKnown && sizes.Install != 0 {
			t.Fatalf("%q: the installed size is unknown yet %d", output, sizes.Install)
		}
	})
}
