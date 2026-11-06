package task

import "github.com/spaiter/spaiter-vpn/core/common/xray"

// Close returns a func() that closes v.
func Close(v interface{}) func() error {
	return func() error {
		return common.Close(v)
	}
}
