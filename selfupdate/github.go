package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Release 是 GitHub release API 响应的子集。
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Assets  []asset `json:"assets"`
}

// gitDescribeSuffix 匹配 git describe 在提交领先于 tag 时追加的 "-<n>-g<sha>" 尾部。
var gitDescribeSuffix = regexp.MustCompile(`-\d+-g[0-9a-f]+$`)

// repoLatestURL 是 GitHub API 端点，声明为变量以便测试重定向到本地服务器。
var repoLatestURL = "https://api.github.com/repos/nange/easyss/releases/latest"

// repoReleaseTagURL 是获取指定 tag 的 release 的端点模板，同样可被测试重定向。
var repoReleaseTagURL = "https://api.github.com/repos/nange/easyss/releases/tags/%s"

var errReleaseNotFound = errors.New("release not found")

// CheckLatest 从 /releases/latest 取最新正式 release：预发布与草稿由 GitHub 排除。
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

// checkTag 取指定 tag 的 release，该端点也会返回预发布版本。
// tag 必须完全一致，不做前缀补全；未找到时返回包装了 errReleaseNotFound 的错误。
func checkTag(ctx context.Context, c *Client, tag string) (*Release, error) {
	rawURL := fmt.Sprintf(repoReleaseTagURL, url.PathEscape(tag))
	resp, err := c.Get(ctx, rawURL, map[string]string{
		"Accept": "application/vnd.github+json",
	})
	if err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: tag %s", errReleaseNotFound, tag)
		}
		return nil, fmt.Errorf("query release %s: %w", tag, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release %s: %w", tag, err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release %s response has no tag", tag)
	}
	return &rel, nil
}

// num 是 "rc9"、"beta9.1" 这类预发布版本号的数值分解。
type num struct {
	major, minor int
}

// parseNumericPre 把预发布版本号拆成前导标识符与尾部数字部分，返回 false 表示
// 没有数字尾部，调用方应回退到 semver 库的排序规则。
func parseNumericPre(pre string) (string, num, bool) {
	i := 0
	for i < len(pre) && (pre[i] < '0' || pre[i] > '9') {
		i++
	}
	if i == 0 || i == len(pre) {
		return "", num{}, false
	}
	prefix := pre[:i]
	parts := strings.SplitN(pre[i:], ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", num{}, false
	}
	n := num{major: major}
	if len(parts) == 2 {
		n.minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return "", num{}, false
		}
	}
	return prefix, n, true
}

func (a num) compare(b num) int {
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

func cmpUint64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// HasNewVersion 报告 latestTag 是否比 currentTag 更新。空的 currentTag（开发构建）
// 总是更新；currentTag 的 git describe 后缀会被剥掉；解析失败时退回不等比较。
func HasNewVersion(currentTag, latestTag string) bool {
	if currentTag == "" {
		return true
	}
	currentTag = gitDescribeSuffix.ReplaceAllString(currentTag, "")

	cur, curErr := semver.NewVersion(currentTag)
	lat, latErr := semver.NewVersion(latestTag)
	if curErr != nil || latErr != nil {
		return currentTag != latestTag
	}
	return newerThan(lat, cur)
}

// newerThan 报告 a 是否比 b 更新。与 semver 库唯一的分歧：前导标识符相同的数字
// 预发布号按数值比较，否则规范按字典序会把 rc9 排在 rc11 之上。
func newerThan(a, b *semver.Version) bool {
	if cmp := cmpUint64(a.Major(), b.Major()); cmp != 0 {
		return cmp > 0
	}
	if cmp := cmpUint64(a.Minor(), b.Minor()); cmp != 0 {
		return cmp > 0
	}
	if cmp := cmpUint64(a.Patch(), b.Patch()); cmp != 0 {
		return cmp > 0
	}
	ap, bp := a.Prerelease(), b.Prerelease()
	if ap == "" && bp == "" {
		return false
	}
	if ap == "" {
		return true
	}
	if bp == "" {
		return false
	}
	apre, an, aok := parseNumericPre(ap)
	bpre, bn, bok := parseNumericPre(bp)
	if aok && bok && apre == bpre {
		return an.compare(bn) > 0
	}
	return a.Compare(b) > 0
}

// pickAssetFor 按 CI 的资产命名规范（<product>-<goos>-<goarch>.zip）挑选 release 资产，
// 该命名是与 Makefile 打包产物的对外契约，改名会让老客户端无法自更新。
func pickAssetFor(rel *Release, product Product, goos, goarch string) *asset {
	name := product.assetName(goos, goarch)
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i]
		}
	}
	return nil
}

func pickAsset(rel *Release, goos, goarch string) *asset {
	return pickAssetFor(rel, ProductClient, goos, goarch)
}
