package ip

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	xForwardedFor = "X-Forwarded-For"
)

// Strategy a strategy for IP selection.
type Strategy interface {
	GetIP(req *http.Request) string
}

// RemoteAddrStrategy a strategy that always return the remote address.
type RemoteAddrStrategy struct{}

// GetIP returns the selected IP.
func (s *RemoteAddrStrategy) GetIP(req *http.Request) string {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// DepthStrategy a strategy based on the depth inside the X-Forwarded-For from right to left.
type DepthStrategy struct {
	Depth int
}

// GetIP return the selected IP.
func (s *DepthStrategy) GetIP(req *http.Request) string {
	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")
	ret := req.RemoteAddr

	if len(xffs)-s.Depth < 0 {
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err == nil {
			ret = ip
		}
	} else {
		ret = strings.TrimSpace(xffs[len(xffs)-s.Depth])
	}
	fmt.Printf("\n\nDepthStrategy.GetIP(%d). XFFS: '%s' RemoteAddr: %s Ret: %s\n\n", s.Depth, xff, req.RemoteAddr, ret)
	return ret
}

// CheckerStrategy a strategy based on an IP Checker
// allows to check that addresses are in a trusted IPs.
type CheckerStrategy struct {
	Checker *Checker
}

// GetIP return the selected IP.
func (s *CheckerStrategy) GetIP(req *http.Request) string {
	if s.Checker == nil {
		return ""
	}

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffTrimmed := strings.TrimSpace(xffs[i])
		if contain, _ := s.Checker.Contains(xffTrimmed); !contain {
			return xffTrimmed
		}
	}
	return ""
}
