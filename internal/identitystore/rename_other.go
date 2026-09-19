//go:build !linux

package identitystore

// renameNoReplace moves a directory under a name that must be free.
func renameNoReplace(oldPath, newPath string) error {
	return renameNoReplaceFallback(oldPath, newPath)
}
