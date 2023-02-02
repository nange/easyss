//go:build !darwin

package util

func SetSysDNS(v []string) error {
	return nil
}

func SysDNS() ([]string, error) {
	return nil, nil
}
