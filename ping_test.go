package ping

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

func Test_byteSliceOfSize(t *testing.T) {
	n := 2
	slice := byteSliceOfSize(n)

	assert.Equal(t, n, len(slice))
	assert.Equal(t, []byte{1, 1}, slice)
}

func Test_ipv4Payload(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{
			name:  "no header",
			input: []byte{1, 2},
			want:  []byte{1, 2},
		},
		{
			name: "header length 5",
			input: []byte{
				0b00000101, 0, 0, 0, 0,
				1, 1, 1, 1, 1,
				2, 2, 2, 2, 2,
				3, 3, 3, 3, 3,
				4, 4, 4, 4, 4,
			},
			want: []byte{
				4, 4, 4, 4, 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipv4Payload(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_bytesToTime(t *testing.T) {
	tm := time.Now()
	b := timeToBytes(tm)
	tmGot := bytesToTime(b)

	assert.Equal(t, tm.UnixNano(), tmGot.UnixNano())
}

func Test_isIPv4(t *testing.T) {
	tests := []struct {
		name  string
		input net.IP
		want  bool
	}{
		{
			name:  "valid ipv4 IP",
			input: net.IP([]byte{1, 1, 1, 1}),
			want:  true,
		},
		{
			name:  "invalid ipv4 IP",
			input: net.IP([]byte{1, 1, 1, 1, 1}),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPv4(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_isIPv6(t *testing.T) {
	tests := []struct {
		name  string
		input net.IP
		want  bool
	}{
		{
			name: "valid ipv6 IP",
			input: net.IP([]byte{
				1, 1, 1, 1,
				1, 1, 1, 1,
				1, 1, 1, 1,
				1, 1, 1, 1,
			}),
			want: true,
		},
		{
			name:  "invalid ipv6 IP",
			input: net.IP([]byte{1, 1, 1, 1}),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPv6(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetIPAddr(t *testing.T) {
	googleAddr, err := net.ResolveIPAddr("ip", "www.google.com")
	if err != nil {
		t.Fatal("Cannot resolve www.google.com, can't run tests")
	}

	p := New("localhost")
	err = p.Resolve()
	assert.NoError(t, err)
	assert.Equal(t, "localhost", p.Addr())

	// Set IPAddr to google
	p.SetIPAddr(googleAddr)
	assert.Equal(t, googleAddr.String(), p.Addr())
}

func TestStatisticsLossy(t *testing.T) {
	// Create a localhost ipv4 pinger
	p, err := NewPinger("localhost")
	assert.NoError(t, err)
	assert.Equal(t, "localhost", p.Addr())

	p.PacketsSent = 20
	p.PacketsRecv = 10
	p.rtts = []time.Duration{
		time.Duration(10),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(10000),
		time.Duration(1000),
		time.Duration(800),
		time.Duration(1000),
		time.Duration(40),
		time.Duration(100000),
		time.Duration(1000),
	}

	stats := p.Statistics()
	assert.Equal(t, 10, stats.PacketsRecv)
	assert.Equal(t, 20, stats.PacketsSent)
	assert.Equal(t, 50.0, stats.PacketLoss)
	assert.Equal(t, time.Duration(10), stats.MinRtt)
	assert.Equal(t, time.Duration(100000), stats.MaxRtt)
	assert.Equal(t, time.Duration(11585), stats.AvgRtt)
	assert.Equal(t, time.Duration(29603), stats.StdDevRtt)
}

func TestStatisticsSunny(t *testing.T) {
	// Create a localhost ipv4 pinger
	p, err := NewPinger("localhost")
	assert.NoError(t, err)
	assert.Equal(t, "localhost", p.Addr())

	p.PacketsSent = 10
	p.PacketsRecv = 10
	p.rtts = []time.Duration{
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
		time.Duration(1000),
	}

	stats := p.Statistics()
	assert.Equal(t, 10, stats.PacketsRecv)
	assert.Equal(t, 10, stats.PacketsSent)
	assert.Equal(t, 0.0, stats.PacketLoss)
	assert.Equal(t, time.Duration(1000), stats.MinRtt)
	assert.Equal(t, time.Duration(1000), stats.MaxRtt)
	assert.Equal(t, time.Duration(1000), stats.AvgRtt)
	assert.Equal(t, time.Duration(0), stats.StdDevRtt)
}

func TestNewPingerInvalid(t *testing.T) {
	_, err := NewPinger("127.0.0.0.0.1")
	assert.Equal(t, err.Error(), "lookup 127.0.0.0.0.1: no such host")

	_, err = NewPinger("127..0.0.0.1")
	assert.Equal(t, err.Error(), "lookup 127..0.0.0.1: no such host")

	_, err = NewPinger("wtf")
	assert.Equal(t, err.Error(), "lookup wtf: no such host")

	_, err = NewPinger(":::1")
	assert.Equal(t, err.Error(), "lookup :::1: no such host")

	_, err = NewPinger("ipv5.google.com")
	assert.Equal(t, err.Error(), "lookup ipv5.google.com: no such host")
}

func TestNewPingerValid(t *testing.T) {
	p, err := NewPinger("www.google.com")
	assert.NoError(t, err)
	assert.Equal(t, "www.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	assert.NotEqual(t, "www.google.com", p.IPAddr().String())
	assert.True(t, isIPv4(p.IPAddr().IP))
	assert.False(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	assert.True(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("localhost")
	assert.NoError(t, err)
	assert.Equal(t, "localhost", p.Addr())
	// DNS names should resolve into IP addresses
	assert.NotEqual(t, "localhost", p.IPAddr().String())
	assert.True(t, isIPv4(p.IPAddr().IP))
	assert.False(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	assert.True(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("127.0.0.1")
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1", p.Addr())
	assert.True(t, isIPv4(p.IPAddr().IP))
	assert.False(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	assert.True(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("ipv6.google.com")
	assert.NoError(t, err)
	assert.Equal(t, "ipv6.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	assert.NotEqual(t, "ipv6.google.com", p.IPAddr().String())
	assert.True(t, isIPv6(p.IPAddr().IP))
	assert.False(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	assert.True(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv6(p.IPAddr().IP))

	p, err = NewPinger("::1")
	assert.NoError(t, err)
	assert.Equal(t, "::1", p.Addr())
	assert.True(t, isIPv6(p.IPAddr().IP))
	assert.False(t, p.Privileged())
	// Test that SetPrivileged works
	p.SetPrivileged(true)
	assert.True(t, p.Privileged())
	// Test setting to ipv4 address
	err = p.SetAddr("www.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv4(p.IPAddr().IP))
	// Test setting to ipv6 address
	err = p.SetAddr("ipv6.google.com")
	assert.NoError(t, err)
	assert.True(t, isIPv6(p.IPAddr().IP))
}
