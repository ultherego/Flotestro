package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/paging"
)

// Entity tags for the settings two operators may edit at once.

// etagOf derives a weak entity tag from the parts that change whenever the
// record does: a timestamp, a list of identifiers, a version.
func etagOf(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return `W/"` + hex.EncodeToString(sum[:8]) + `"`
}

// etagOfTime is the tag of a record versioned by its updated_at column.
func etagOfTime(updatedAt time.Time) string {
	return etagOf(paging.FormatTime(updatedAt))
}

// setETag puts the tag of the served representation on the response.
func setETag(w http.ResponseWriter, tag string) {
	w.Header().Set("ETag", tag)
}

// requireMatch enforces the If-Match precondition of a write. Without the
// header the write proceeds.
func requireMatch(w http.ResponseWriter, r *http.Request, current string) bool {
	header := strings.TrimSpace(r.Header.Get("If-Match"))
	if header == "" {
		return true
	}
	if current != "" {
		for _, candidate := range strings.Split(header, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || opaqueTag(candidate) == opaqueTag(current) {
				return true
			}
		}
	}
	if current != "" {
		setETag(w, current)
	}
	problem(w, http.StatusPreconditionFailed, "precondition_failed",
		"the record changed since it was read; read it again and repeat the write with its current ETag")
	return false
}

// opaqueTag strips the weakness marker: two tags with the same opaque
// part name the same version.
func opaqueTag(tag string) string {
	return strings.TrimPrefix(tag, "W/")
}
