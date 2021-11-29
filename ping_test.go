package ping

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

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
	p := New("localhost")
	err := p.Resolve()
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
	p := New("localhost")
	err := p.Resolve()
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
	p := New("127.0.0.0.0.1")
	err := p.Resolve()
	assert.Equal(t, err.Error(), "lookup 127.0.0.0.0.1: no such host")

	p = New("127..0.0.0.1")
	err = p.Resolve()
	assert.Equal(t, err.Error(), "lookup 127..0.0.0.1: no such host")

	p = New("wtf.invalid")
	err = p.Resolve()
	assert.Equal(t, err.Error(), "lookup wtf.invalid: no such host")

	p = New(":::1")
	err = p.Resolve()
	assert.Equal(t, err.Error(), "lookup :::1: no such host")

	p = New("ipv5.google.com")
	err = p.Resolve()
	assert.Equal(t, err.Error(), "lookup ipv5.google.com: no such host")
}

func TestNewPingerValid(t *testing.T) {
	p := New("www.google.com")
	err := p.Resolve()
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
	assert.False(t, isIPv4(p.IPAddr().IP))

	p = New("localhost")
	err = p.Resolve()
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
	assert.False(t, isIPv4(p.IPAddr().IP))

	p = New("127.0.0.1")
	err = p.Resolve()
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
	assert.False(t, isIPv4(p.IPAddr().IP))

	p = New("ipv6.google.com")
	err = p.Resolve()
	assert.NoError(t, err)
	assert.Equal(t, "ipv6.google.com", p.Addr())
	// DNS names should resolve into IP addresses
	assert.NotEqual(t, "ipv6.google.com", p.IPAddr().String())
	assert.False(t, isIPv4(p.IPAddr().IP))
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
	assert.False(t, isIPv4(p.IPAddr().IP))

	p = New("::1")
	err = p.Resolve()
	assert.NoError(t, err)
	assert.Equal(t, "::1", p.Addr())
	assert.False(t, isIPv4(p.IPAddr().IP))
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
	assert.False(t, isIPv4(p.IPAddr().IP))
}

func BenchmarkProcessPacket(b *testing.B) {
	pinger := New("127.0.0.1")
	pinger.Resolve()

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.network = "ip4:icmp"
	pinger.id = 123
	pinger.Tracker = 456

	t := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	for k := 0; k < b.N; k++ {
		pinger.processPacket(&pkt)
	}
}

func TestProcessPacket(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe1 := 0
	// this function should be called
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe1++
	}

	data := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}
	pinger.awaitingSequences[pinger.sequence] = struct{}{}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
	assert.True(t, shouldBe1 == 1)
}

func TestProcessPacket_IgnoreNonEchoReplies(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatches
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	data := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
	assert.True(t, shouldBe0 == 0)
}

func TestProcessPacket_IDMismatch(t *testing.T) {
	pinger := makeTestPinger()
	pinger.protocol = "icmp" // ID is only checked on "icmp" protocol
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatches
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	data := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   999999,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
	assert.True(t, shouldBe0 == 0)
}

func TestProcessPacket_TrackerMismatch(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe0 := 0
	// this function should not be called because the tracker is mismatches
	pinger.OnRecv = func(pkt *Packet) {
		shouldBe0++
	}

	data := append(timeToBytes(time.Now()), intToBytes(999)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
	assert.True(t, shouldBe0 == 0)
}

func TestProcessPacket_LargePacket(t *testing.T) {
	pinger := makeTestPinger()
	pinger.Size = 4096

	data := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
}

func TestProcessPacket_PacketTooSmall(t *testing.T) {
	pinger := makeTestPinger()
	data := []byte("foo")

	body := &icmp.Echo{
		ID:   pinger.id,
		Seq:  pinger.sequence,
		Data: data,
	}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.Error(t, err)
}

func TestEmptyIPAddr(t *testing.T) {
	_, err := NewPinger("")
	assert.Error(t, err)
}
func TestProcessPacket_IgnoresDuplicateSequence(t *testing.T) {
	pinger := makeTestPinger()
	shouldBe1 := 0
	dups := 0

	pinger.OnRecv = func(p *Packet) {
		shouldBe1++
	}

	pinger.OnDuplicateRecv = func(p *Packet) {
		dups++
	}

	data := append(timeToBytes(time.Now()), intToBytes(pinger.Tracker)...)
	if remainSize := pinger.Size - timeSliceLength - trackerLength; remainSize > 0 {
		data = append(data, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   123,
		Seq:  0,
		Data: data,
	}
	// register the sequence as sent
	pinger.awaitingSequences[0] = struct{}{}

	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: body,
	}

	msgBytes, _ := msg.Marshal(nil)

	pkt := packet{
		nbytes: len(msgBytes),
		bytes:  msgBytes,
		ttl:    24,
	}

	err := pinger.processPacket(&pkt)
	assert.NoError(t, err)
	// receive a duplicate
	err = pinger.processPacket(&pkt)
	assert.NoError(t, err)

	// shouldBe1 should be 1 even though 2 packets are received
	assert.False(t, shouldBe1 == 2)
	assert.True(t, shouldBe1 == 1)
	assert.True(t, dups == 1)
	assert.True(t, pinger.PacketsRecvDuplicates == 1)
}

func makeTestPinger() *Pinger {
	pinger := New("127.0.0.1")
	pinger.Resolve()

	pinger.ipv4 = true
	pinger.addr = "127.0.0.1"
	pinger.network = "ip"
	pinger.id = 123
	pinger.Tracker = 456
	pinger.Size = 0

	return pinger
}
