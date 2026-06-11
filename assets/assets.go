package assets

import _ "embed"

var (
	//go:embed geodata/Country-only-cn-private.mmdb
	GeoIPCNPrivate []byte

	//go:embed geodata/direct-list.txt
	GeoSiteDirect []byte

	//go:embed geodata/block-list.txt
	GeoSiteBlock []byte
)
