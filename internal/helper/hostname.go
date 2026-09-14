package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	helperv1 "github.com/ultherego/flotestro/internal/genproto/flotestro/helper/v1"
	"github.com/ultherego/flotestro/internal/modules/hostname"
)

// hostnameFile is where the static name lives on every distribution the
// panel supports; hostnamectl writes it.
const hostnameFile = "/etc/hostname"

// applyHostname renames the host.
//
// The static and the transient name are set together, so the host answers
// to the new name at once and after a reboot. The pretty name is set only
// when the order carries one: hostnamectl without a flag would set it to
// the static name as well, and a pretty name nobody asked for is not a
// change the operator approved. The entries of /etc/hosts that name the old
// hostname follow the rename, with the file from before the first rename
// kept next to it.
func (s *Server) applyHostname(ctx context.Context, request *helperv1.HelperRequest,
	action *helperv1.HostnameRequest) *helperv1.HelperResponse {
	current := strings.TrimSpace(action.GetHostname())
	if err := hostname.Validate(current); err != nil {
		return reject(ErrorMalformed, err.Error())
	}
	if err := hostname.ValidatePretty(action.GetPretty()); err != nil {
		return reject(ErrorMalformed, err.Error())
	}

	release, busy := s.hold(GuardHost, request)
	if busy != nil {
		return busy
	}
	defer release()

	actionCtx, cancel := deadline(ctx, request, time.Minute, 5*time.Minute)
	defer cancel()

	previous := staticHostname()
	result := &helperv1.HostnameResult{Previous: previous, Current: current}
	if previous != current {
		if _, stderr, err := s.tool()(actionCtx, 30*time.Second, "hostnamectl",
			"set-hostname", "--static", "--transient", current); err != nil {
			return reject(ErrorExecFailed, "hostnamectl: "+firstLineOf(stderr))
		}
		result.Changed = true
	}
	if pretty := action.GetPretty(); pretty != "" {
		if _, stderr, err := s.tool()(actionCtx, 30*time.Second, "hostnamectl",
			"set-hostname", "--pretty", pretty); err != nil {
			return reject(ErrorExecFailed, "hostnamectl: "+firstLineOf(stderr))
		}
	}

	// The hosts file follows the name. A failure here does not undo the
	// rename - the host already answers to the new name - but it is not
	// passed over either: the operator is to know the file still names the
	// old one.
	updated, err := rewriteHostsFile(s.hostsPath(), s.hostsPath()+".flotestro-before", previous, current)
	if err != nil {
		response := reject(ErrorExecFailed, "the host was renamed, but /etc/hosts was not updated: "+err.Error())
		response.HostnameResult = result
		return response
	}
	result.HostsFileUpdated = updated

	s.log.Info("the host was renamed", "task_id", request.GetTaskId(),
		"previous", previous, "current", current, "hosts_file_updated", updated)
	return &helperv1.HelperResponse{Accepted: true, HostnameResult: result}
}

// hostsPath returns the file the rename rewrites: the injected one in tests,
// /etc/hosts otherwise.
func (s *Server) hostsPath() string {
	if s.hostsFile != "" {
		return s.hostsFile
	}
	return hostname.HostsPath
}

// staticHostname reads the name the host will have after a reboot. The
// kernel's name is the fallback: on a host without the file the two are the
// same thing.
func staticHostname() string {
	if content, err := os.ReadFile(hostnameFile); err == nil {
		if name := strings.TrimSpace(string(content)); name != "" {
			return name
		}
	}
	name, _ := os.Hostname()
	return name
}

// rewriteHostsFile replaces the old hostname with the new one in the
// entries that name it.
//
// The file from before the first rename by the panel is kept as the backup
// and never overwritten: it is the file the administrator wants back. The
// write is atomic - a half-written hosts file breaks name resolution for
// every local service. A hosts file that is a symbolic link is left alone
// and reported: the helper runs as root and does not write through links.
func rewriteHostsFile(path, backup, previous, current string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symbolic link and is not rewritten", path)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	rewritten, changed := hostname.RewriteHosts(string(content), previous, current)
	if !changed {
		return false, nil
	}
	if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(backup, content, info.Mode().Perm()); err != nil {
			return false, fmt.Errorf("keeping the previous %s: %w", filepath.Base(path), err)
		}
	}
	temporary := path + ".flotestro-tmp"
	if err := os.WriteFile(temporary, []byte(rewritten), info.Mode().Perm()); err != nil {
		return false, err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return false, err
	}
	return true, nil
}
