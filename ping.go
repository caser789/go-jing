package ping

import (
	"golang.org/x/net/ipv4"
	"net"
	"time"
)

// Pinger represents ICMP packet sender/receiver
type Pinger struct {
	ipaddr *net.IPAddr
	addr   string
}

func New(addr string) *Pinger {
	return &Pinger{
		addr: addr,
	}
}

func (p *Pinger) Resolve() error {
	return nil
}

// SetIPAddr sets the ip address of the target host.
func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}

// IPAddr returns the IP address of the target host.
func (p *Pinger) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *Pinger) SetAddr(addr string) error {
	ipaddr, err := net.ResolveIPAddr("ip4:icmp", addr)
	if err != nil {
		return err
	}
	p.addr = addr
	p.ipaddr = ipaddr
	return nil
}

// Addr returns the string ip address of the target host.
func (p *Pinger) Addr() string {
	return p.addr
}

func byteSliceOfSize(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = 1
	}

	return b
}

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2 // each bit for 4 bytes, minimum 5 bits
	return b[hdrlen:]
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}
