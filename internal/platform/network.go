package platform

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func (s *Server) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("invalid destination")
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, errors.New("destination unavailable")
	}
	for _, item := range ips {
		ip := item.IP
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || (ip.IsLoopback() && !strings.HasPrefix(s.cfg.PublicURL, "http:")) {
			return nil, errors.New("destination prohibited")
		}
	}
	for _, item := range ips {
		c, e := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(item.IP.String(), port))
		if e == nil {
			return c, nil
		}
	}
	return nil, errors.New("destination unavailable")
}
func (s *Server) client() (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if s.cfg.CustomCA != "" {
		b, e := os.ReadFile(s.cfg.CustomCA)
		if e != nil || !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("custom CA unavailable")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = s.dial
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
