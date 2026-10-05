package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ultherego/flotestro/internal/hosts"
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
	problem(w, http.StatusPreconditionFailed, "precondition_failed", recordMoved)
	return false
}

// recordMoved is what a write is told when the version it was decided on is
// not the version in the database - whether the If-Match said so or the write
// itself found out.
const recordMoved = "the record changed since it was read; " +
	"read it again and repeat the write with its current ETag"

// hostMoved answers a write of a host's facts that landed on no row because
// somebody wrote it first. The answer is the one a stale If-Match gets,
// because it is the same thing: the version the write was decided on is gone.
func hostMoved(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, hosts.ErrChanged) {
		return false
	}
	problem(w, http.StatusPreconditionFailed, "precondition_failed", recordMoved)
	return true
}

// opaqueTag strips the weakness marker: two tags with the same opaque
// part name the same version.
func opaqueTag(tag string) string {
	return strings.TrimPrefix(tag, "W/")
}
