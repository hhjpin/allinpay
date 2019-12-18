package allinpay

import (
	"net/url"
	"strings"
)

func EncodeURIComponent(str string) string {
	return strings.Replace(url.QueryEscape(str), "+", "%20", -1)
}
