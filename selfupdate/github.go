package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
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

// parsedVersion is a numeric representation of the version tags easyss
// publishes: [v]X.Y.Z with an optional -rcN prerelease.
type parsedVersion struct {
	major, minor, patch int
	rc                  int // -1 when there is no prerelease
}

// parseVersion parses a version tag, returning false for anything outside the
// X.Y.Z[-rcN] shape so the caller can fall back to string comparison. rc
// numbers are compared numerically (rc9 < rc11), which semver would get wrong
// because it compares prerelease identifiers lexically.
func parseVersion(tag string) (parsedVersion, bool) {
	t := strings.TrimPrefix(tag, "v")
	rc := -1
	if i := strings.IndexByte(t, '-'); i >= 0 {
		pre := t[i+1:]
		if !strings.HasPrefix(pre, "rc") {
			return parsedVersion{}, false
		}
		n, err := strconv.Atoi(strings.TrimPrefix(pre, "rc"))
		if err != nil {
			return parsedVersion{}, false
		}
		rc = n
		t = t[:i]
	}
	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return parsedVersion{}, false
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return parsedVersion{}, false
		}
		nums[i] = n
	}
	return parsedVersion{nums[0], nums[1], nums[2], rc}, true
}

// compare returns -1, 0 or 1. A release (no prerelease) is always newer than
// an rc of the same core version, and rc numbers compare numerically.
func (p parsedVersion) compare(o parsedVersion) int {
	for _, pair := range [][2]int{{p.major, o.major}, {p.minor, o.minor}, {p.patch, o.patch}} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	switch {
	case p.rc == -1 && o.rc == -1:
		return 0
	case p.rc == -1:
		return 1
	case o.rc == -1:
		return -1
	case p.rc < o.rc:
		return -1
	case p.rc > o.rc:
		return 1
	default:
		return 0
	}
}

// HasNewVersion reports whether latestTag is newer than currentTag. An empty
// currentTag (development build) always updates. A git describe suffix on
// currentTag is ignored so that a build cut slightly after a release is not
// offered an update to that same release. Tags outside the X.Y.Z[-rcN] shape
// fall back to plain inequality.
func HasNewVersion(currentTag, latestTag string) bool {
	if currentTag == "" {
		return true
	}
	currentTag = gitDescribeSuffix.ReplaceAllString(currentTag, "")

	cur, curOK := parseVersion(currentTag)
	lat, latOK := parseVersion(latestTag)
	if !curOK || !latOK {
		return currentTag != latestTag
	}
	return lat.compare(cur) > 0
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
