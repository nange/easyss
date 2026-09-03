package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/coreos/go-semver/semver"
)

// Asset is a downloadable file attached to a release.
type Asset struct {
	Name string `json:"name"`
	// BrowserDownloadURL is the direct download URL.
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Release is the subset of the GitHub release API response we need.
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Assets  []Asset `json:"assets"`
}

// gitDescribeSuffix matches the "-<n>-g<sha>" tail git describe appends when
// the built commit is ahead of the tag, e.g. "v3.0.1-5-gabc1234".
var gitDescribeSuffix = regexp.MustCompile(`-\d+-g[0-9a-f]+$`)

// CheckLatest fetches the latest published release from GitHub. The
// /releases/latest endpoint only returns full releases: pre-releases and
// drafts are excluded by GitHub itself.
func CheckLatest(ctx context.Context, c *Client) (*Release, error) {
	resp, err := c.Get(ctx, repoLatestURL, map[string]string{
		"Accept": "application/vnd.github+json",
	})
	if err != nil {
		return nil, fmt.Errorf("query latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode latest release: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("latest release response has no tag")
	}
	return &rel, nil
}

// rcNum is the numeric decomposition of an "rcN" (or "rcN.M") prerelease.
type rcNum struct {
	major, minor int
}

// parseRC extracts the numeric parts of an "rcN"/"rcN.M" prerelease. It
// returns false for any other prerelease shape.
func parseRC(pre semver.PreRelease) (rcNum, bool) {
	rest := strings.TrimPrefix(string(pre), "rc")
	parts := strings.SplitN(rest, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return rcNum{}, false
	}
	rc := rcNum{major: major}
	if len(parts) == 2 {
		rc.minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return rcNum{}, false
		}
	}
	return rc, true
}

// compare returns -1, 0 or 1.
func (a rcNum) compare(b rcNum) int {
	switch {
	case a.major != b.major:
		return cmpInt(a.major, b.major)
	case a.minor != b.minor:
		return cmpInt(a.minor, b.minor)
	default:
		return 0
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// HasNewVersion reports whether latestTag is newer than currentTag. An empty
// currentTag (development build) always updates. A git describe suffix on
// currentTag is ignored so that a build cut slightly after a release is not
// offered an update to that same release. Tags that fail to parse fall back
// to plain inequality.
func HasNewVersion(currentTag, latestTag string) bool {
	if currentTag == "" {
		return true
	}
	currentTag = gitDescribeSuffix.ReplaceAllString(currentTag, "")

	// coreos/go-semver does not accept a leading "v".
	cur, curErr := semver.NewVersion(strings.TrimPrefix(currentTag, "v"))
	lat, latErr := semver.NewVersion(strings.TrimPrefix(latestTag, "v"))
	if curErr != nil || latErr != nil {
		return currentTag != latestTag
	}
	return newerThan(lat, cur)
}

// newerThan reports whether a is a newer release than b. Core version parts
// are compared like the library; the only divergence is that rc prereleases
// are compared numerically (rc9 < rc11), because the semver spec compares
// prerelease identifiers lexically, which would rank rc9 above rc11.
func newerThan(a, b *semver.Version) bool {
	if cmp := cmpInt64(a.Major, b.Major); cmp != 0 {
		return cmp > 0
	}
	if cmp := cmpInt64(a.Minor, b.Minor); cmp != 0 {
		return cmp > 0
	}
	if cmp := cmpInt64(a.Patch, b.Patch); cmp != 0 {
		return cmp > 0
	}
	// Same core version: a release (no prerelease) is newer than a prerelease.
	if a.PreRelease == "" && b.PreRelease == "" {
		return false
	}
	if a.PreRelease == "" {
		return true
	}
	if b.PreRelease == "" {
		return false
	}
	// Numeric rc comparison, falling back to the library's ordering for any
	// other prerelease shape.
	ar, aok := parseRC(a.PreRelease)
	br, bok := parseRC(b.PreRelease)
	if aok && bok {
		return ar.compare(br) > 0
	}
	return a.Compare(*b) > 0
}

// PickAsset returns the release asset for the given platform, following the
// CI naming scheme (easyss-<goos>-<goarch>.zip), or nil when absent.
func PickAsset(rel *Release, goos, goarch string) *Asset {
	name := fmt.Sprintf("easyss-%s-%s.zip", goos, goarch)
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i]
		}
	}
	return nil
}
