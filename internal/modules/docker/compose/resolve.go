package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// ResolvedImage is the digest an image reference resolves to and where
// the answer came from.
type ResolvedImage struct {
	Digest string
	Source string
}

// ImageResolver turns an image reference into the digest that will run.
type ImageResolver func(ctx context.Context, image string) (ResolvedImage, error)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validDigest(digest string) bool {
	return digestPattern.MatchString(digest)
}

// pinnedDigest returns the digest an image reference carries itself, or
// nothing for a reference by tag.
func pinnedDigest(image string) string {
	_, digest, found := strings.Cut(image, "@")
	if !found || !validDigest(digest) {
		return ""
	}
	return digest
}

// PinReference replaces the tag of a reference with the digest.
func PinReference(image, digest string) string {
	if pinnedDigest(image) != "" {
		return image
	}
	return repositoryOf(image) + "@" + digest
}

// repositoryOf strips the tag and the digest off a reference.
func repositoryOf(image string) string {
	repository := image
	if at := strings.LastIndex(repository, "@"); at >= 0 {
		repository = repository[:at]
	}
	slash := strings.LastIndex(repository, "/")
	if colon := strings.LastIndex(repository, ":"); colon > slash {
		repository = repository[:colon]
	}
	return repository
}

// ResolveWithDocker resolves tags with the Docker client on the host.
func ResolveWithDocker(docker Runner) ImageResolver {
	return func(ctx context.Context, image string) (ResolvedImage, error) {
		var registryErr error
		stdout, stderr, err := docker(ctx, "manifest", "inspect", "--verbose", image)
		if err != nil {
			registryErr = fmt.Errorf("%s", firstLine(stderr))
		} else if digest, err := digestFromManifest(stdout, runtime.GOARCH); err != nil {
			registryErr = err
		} else {
			return ResolvedImage{Digest: digest, Source: DigestFromRegistry}, nil
		}

		stdout, _, err = docker(ctx, "image", "inspect", "--format", "{{json .RepoDigests}}", image)
		if err != nil {
			return ResolvedImage{}, fmt.Errorf("the registry did not answer (%v) and the image is not on the host", registryErr)
		}
		digest, err := digestFromLocalImage(stdout, image)
		if err != nil {
			return ResolvedImage{}, fmt.Errorf("the registry did not answer (%v) and the host has no digest for the image: %v",
				registryErr, err)
		}
		return ResolvedImage{Digest: digest, Source: DigestFromLocal}, nil
	}
}

// manifestEntry is one object of "docker manifest inspect --verbose": a
// single manifest, or one element of the list for a multi-platform image.
type manifestEntry struct {
	Descriptor struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"Descriptor"`
}

// digestFromManifest picks the manifest that will run on this host.
func digestFromManifest(output, architecture string) (string, error) {
	output = strings.TrimSpace(output)
	var entries []manifestEntry
	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &entries); err != nil {
			return "", fmt.Errorf("unreadable manifest list: %w", err)
		}
	} else {
		var single manifestEntry
		if err := json.Unmarshal([]byte(output), &single); err != nil {
			return "", fmt.Errorf("unreadable manifest: %w", err)
		}
		entries = []manifestEntry{single}
	}
	if len(entries) == 1 && validDigest(entries[0].Descriptor.Digest) {
		platform := entries[0].Descriptor.Platform
		if platform.Architecture == "" || platform.Architecture == architecture {
			return entries[0].Descriptor.Digest, nil
		}
	}
	for _, entry := range entries {
		platform := entry.Descriptor.Platform
		if platform.OS == "linux" && platform.Architecture == architecture &&
			validDigest(entry.Descriptor.Digest) {
			return entry.Descriptor.Digest, nil
		}
	}
	return "", fmt.Errorf("the manifest has no linux/%s image", architecture)
}

// digestFromLocalImage reads the digest the host recorded when it pulled the
// image.
func digestFromLocalImage(output, image string) (string, error) {
	var repoDigests []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &repoDigests); err != nil {
		return "", fmt.Errorf("unreadable image record: %w", err)
	}
	repository := repositoryOf(image)
	for _, entry := range repoDigests {
		name, digest, found := strings.Cut(entry, "@")
		if !found || !validDigest(digest) {
			continue
		}
		if sameRepository(name, repository) {
			return digest, nil
		}
	}
	if len(repoDigests) == 0 {
		return "", fmt.Errorf("the image was built on the host and has no registry digest")
	}
	return "", fmt.Errorf("the host has the image under another repository name")
}

// sameRepository compares repository names the way the client does: the
// default registry and the library namespace are implied for a bare name.
func sameRepository(a, b string) bool {
	return canonicalRepository(a) == canonicalRepository(b)
}

func canonicalRepository(name string) string {
	registry, path := "docker.io", name
	first, rest, found := strings.Cut(name, "/")
	// A first segment without a dot or a colon and different from
	// "localhost" is a namespace on Docker Hub, not a registry host.
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		registry, path = first, rest
	}
	switch registry {
	case "docker.io", "index.docker.io", "registry-1.docker.io":
		registry = "docker.io"
		if !strings.Contains(path, "/") {
			path = "library/" + path
		}
	}
	return registry + "/" + path
}
