//go:build !headless

package main

import "github.com/nange/easyss/v3/selfupdate"

// selfupdateProduct 返回在托盘构建中由 "selfupdate" 子命令更新的发布产品。
func selfupdateProduct() selfupdate.Product {
	return selfupdate.ProductClient
}
