package util

import (
	"regexp"
	"strconv"
	"strings"
)

var ipreg = regexp.MustCompile(`^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){3}$`)

func IsIP(ip string) bool {
	return ipreg.MatchString(ip)
}

func IsPrivateIP(ip string) bool {
	if !IsIP(ip) {
		return false
	}
	if IsTypeAIP(ip) || IsTypeBIP(ip) || IsTypeCIP(ip) {
		return true
	}
	return false
}

// A类ip: 10.0.0.0 - 10.255.255.255
func IsTypeAIP(ip string) bool {
	ipitems := strings.Split(ip, ".")
	if len(ipitems) != 4 {
		return false
	}

	first, err := strconv.ParseInt(ipitems[0], 10, 64)
	if err != nil {
		return false
	}
	if first != 10 {
		return false
	}

	return true
}

// B类ip: 172.16.0.0 - 172.31.255.255
func IsTypeBIP(ip string) bool {
	ipitems := strings.Split(ip, ".")
	if len(ipitems) != 4 {
		return false
	}

	first, err := strconv.ParseInt(ipitems[0], 10, 64)
	if err != nil {
		return false
	}
	second, err := strconv.ParseInt(ipitems[1], 10, 64)
	if err != nil {
		return false
	}

	if first != 172 {
		return false
	}
	if second < 16 || second > 31 {
		return false
	}

	return true
}

// C类ip: 192.168.0.0-192.168.255.255
func IsTypeCIP(ip string) bool {
	ipitems := strings.Split(ip, ".")
	if len(ipitems) != 4 {
		return false
	}

	first, err := strconv.ParseInt(ipitems[0], 10, 64)
	if err != nil {
		return false
	}
	second, err := strconv.ParseInt(ipitems[1], 10, 64)
	if err != nil {
		return false
	}

	if first != 192 || second != 168 {
		return false
	}

	return true
}
