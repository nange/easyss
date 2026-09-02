package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/Masterminds/semver/v3"
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

// HasNewVersion reports whether latestTag is newer than currentTag. An empty
// currentTag (development build) always updates. A git describe suffix on
// currentTag is ignored so that a build cut slightly after a release is not
// offered an update to that same release. Tags that are not valid semver
// fall back to plain inequality.
func HasNewVersion(currentTag, latestTag string) bool {
	if currentTag == "" {
		return true
	}
	currentTag = gitDescribeSuffix.ReplaceAllString(currentTag, "")

	curVer, curErr := semver.NewVersion(currentTag)
	latVer, latErr := semver.NewVersion(latestTag)
	if curErr != nil || latErr != nil {
		return currentTag != latestTag
	}
	return latVer.GreaterThan(curVer)
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
