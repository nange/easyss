package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// asset 是挂在 release 下的一个可下载文件。
type asset struct {
	Name string `json:"name"`
	// BrowserDownloadURL 是直接下载 URL。
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Release 是我们需要的 GitHub release API 响应的子集。
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Assets  []asset `json:"assets"`
}

// gitDescribeSuffix 匹配 git describe 在构建提交领先于 tag 时追加的
// "-<n>-g<sha>" 尾部，例如 "v3.0.1-5-gabc1234"。
var gitDescribeSuffix = regexp.MustCompile(`-\d+-g[0-9a-f]+$`)

// repoLatestURL 是获取最新 release 的 GitHub API 端点。它是变量而非常量，
// 以便测试将其重定向到本地服务器。
var repoLatestURL = "https://api.github.com/repos/nange/easyss/releases/latest"

// CheckLatest 从 GitHub 获取最新已发布的 release。/releases/latest 端点
// 只返回正式 release：预发布（pre-release）和草稿（draft）由 GitHub 自行排除。
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

// num 是形如 "prefixN"（或 "prefixN.M"）的预发布版本号的数值分解，
// 例如 "rc9" 或 "beta9.1"。
type num struct {
	major, minor int
}

// parseNumericPre 将预发布版本号拆分为前导标识符（第一个数字之前的非数字
// 字符，如字母、短横线、点号）与尾部数字部分："rc9" -> ("rc", {9,0})，
// "rc9.1" -> ("rc", {9,1})，"beta12" -> ("beta", {12,0})。对没有数字尾部的
// 形式（如 "alpha" 或纯数字预发布版本号）返回 false，让调用方回退到库的
// 排序规则。
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

// compare 返回 -1、0 或 1。
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

// HasNewVersion 报告 latestTag 是否比 currentTag 更新。空的 currentTag
// （开发构建）总是更新。currentTag 上的 git describe 后缀会被忽略，这样
// 在 release 之后不久切出的构建不会被提示更新到同一个 release。解析失败的
// tag 回退到简单的不等比较。
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

// newerThan 报告 a 是否比 b 更新的 release。核心版本号部分与库的规则一致；
// 唯一的差异是：前导标识符相同且带数字尾部的预发布版本号（"rc9"、"beta12"）
// 按数值比较（rc9 < rc11，beta9 < beta11），因为 semver 规范按字典序比较
// 预发布标识符，那样会把 rc9 排在 rc11 之上。
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
	// 核心版本相同：正式版（无预发布标识）比预发布版更新。
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
	// 仅当两者前导标识符相同时才比较数值；
	// 其他情况回退到库的排序规则。
	apre, an, aok := parseNumericPre(ap)
	bpre, bn, bok := parseNumericPre(bp)
	if aok && bok && apre == bpre {
		return an.compare(bn) > 0
	}
	return a.Compare(b) > 0
}

// pickAssetFor 返回给定产品和平台的 release 资产，遵循 CI 命名规范
// （<product>-<goos>-<goarch>.zip），不存在时返回 nil。
func pickAssetFor(rel *Release, product Product, goos, goarch string) *asset {
	name := product.assetName(goos, goarch)
	for i := range rel.Assets {
		if rel.Assets[i].Name == name {
			return &rel.Assets[i]
		}
	}
	return nil
}

// pickAsset 返回给定平台的客户端 release 资产，遵循 CI 命名规范
// （easyss-<goos>-<goarch>.zip），不存在时返回 nil。
func pickAsset(rel *Release, goos, goarch string) *asset {
	return pickAssetFor(rel, ProductClient, goos, goarch)
}
