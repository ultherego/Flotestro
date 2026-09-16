//go:build !linux

package identitystore

// renameNoReplace moves a directory under a name that must be free. Only
// Linux offers the check and the move as one step; elsewhere the store
// checks first and moves second.
func renameNoReplace(oldPath, newPath string) error {
	return renameNoReplaceFallback(oldPath, newPath)
}
