package ping

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"log"
	"math"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	timeSliceLength  = 8
	trackerLength    = 8
	protocolICMP     = 1
	protocolIPv6ICMP = 58
)

var (
	ipv4Proto = map[string]string{"icmp": "ip4:icmp", "udp": "udp4"}
	ipv6Proto = map[string]string{"icmp": "ip6:ipv6-icmp", "udp": "udp6"}
)

// Statistics represent the stats of a currently running or finished
// pinger operation.
type Statistics struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketsLoss is the number of packets lost.
	PacketLoss float64

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// StdDevRtt is standard deviation round-trip times sent via this pinger.
	StdDevRtt time.Duration

	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int
}

// Pinger represents a packet sender/receiver.
type Pinger struct {
	// Interval is the wait time between each packet send. Default is 1s.
	Interval time.Duration

	// Timeout specifies a timeout before ping exits, regardless of how many
	// packets have been received.
	Timeout time.Duration

	// Count tells pinger to stop after sending (and receiving) Count echo
	// packets. If this option is not specified, pinger will operate until
	// interrupted.
	Count int

	// Debug runs in debug mode
	Debug bool

	// Number of packets sent
	PacketsSent int

	// Number of packets received
	PacketsRecv int

	// Number of duplicate packets received
	PacketsRecvDuplicates int

	// Round trip time statistics
	minRtt    time.Duration
	maxRtt    time.Duration
	avgRtt    time.Duration
	stdDevRtt time.Duration
	stddevm2  time.Duration
	statsMu   sync.RWMutex

	// If true, keep a record of rtts of all received packets.
	// Set to false to avoid memory bloat for long running pings.
	RecordRtts bool

	// rtts is all of the Rtts
	rtts []time.Duration

	// OnSetup is called when Pinger has finished setting up the listening socket.
	OnSetup func()

	// OnSend is called when Pinger sends a packet
	OnSend func(*Packet)

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Statistics)

	// OnDuplicateRecv is called when a packet is received that has already been received
	OnDuplicateRecv func(*Packet)

	// Tracker: Used to uniquely identify packets
	Tracker uint64

	// Source is the source IP address
	Source string

	// Channel and mutex used to communicate when the Pinger should stop between goroutines.
	done chan interface{}
	lock sync.Mutex

	ipaddr *net.IPAddr
	addr   string

	ipv4     bool
	Size     int
	id       int
	sequence int
	// network is one of "ip", "ip4", "ip6".
	network string
	// protocol is "icmp" or "udp"
	protocol          string
	awaitingSequences map[int]struct{}

	logger Logger
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// Addr is the string address of the host being pinged.
	Addr string

	// Nbytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number
	Seq int

	// TTL is the TTL on the packet
	Ttl int
}

// New returns a new Pinger struct pointer
func New(addr string) *Pinger {
	r := rand.New(rand.NewSource(getSeed()))

	return &Pinger{
		Count: -1,

		Interval:   time.Second,
		Size:       timeSliceLength + trackerLength,
		Timeout:    time.Duration(math.MaxInt64),
		Tracker:    r.Uint64(),
		RecordRtts: true,

		addr:              addr,
		done:              make(chan interface{}),
		id:                r.Intn(math.MaxUint16),
		ipaddr:            nil,
		ipv4:              false,
		network:           "ip",
		protocol:          "udp",
		awaitingSequences: map[int]struct{}{},
		logger:            StdLogger{Logger: log.New(log.Writer(), log.Prefix(), log.Flags())},
	}
}

// NewPinger returns a new Pinger and resolves the address.
func NewPinger(addr string) (*Pinger, error) {
	p := New(addr)
	return p, p.Resolve()
}

// SetLogger sets the logger to be used to log events from the pinger.
func (p *Pinger) SetLogger(logger Logger) {
	p.logger = logger
}

// SetIPAddr sets the ip address of the target host.
func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}

func (p *Pinger) updateStatistics(pkt *Packet) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()

	p.PacketsRecv++
	if p.RecordRtts {
		p.rtts = append(p.rtts, pkt.Rtt)
	}
	if p.PacketsRecv == 1 || pkt.Rtt < p.minRtt {
		p.minRtt = pkt.Rtt
	}

	if pkt.Rtt > p.maxRtt {
		p.maxRtt = pkt.Rtt
	}

	pktCount := time.Duration(p.PacketsRecv)
	// welford's online method for stddev
	// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
	delta := pkt.Rtt - p.avgRtt
	p.avgRtt += delta / pktCount
	delta2 := pkt.Rtt - p.avgRtt
	p.stddevm2 += delta * delta2

	p.stdDevRtt = time.Duration(math.Sqrt(float64(p.stddevm2 / pktCount)))
}

// Resolve does the DNS lookup for the Pinger address and sets IP protocol.
func (p *Pinger) Resolve() error {
	if len(p.addr) == 0 {
		return errors.New("addr cannot be empty")
	}
	ipaddr, err := net.ResolveIPAddr(p.network, p.addr)
	if err != nil {
		return err
	}

	p.ipv4 = isIPv4(ipaddr.IP)

	p.ipaddr = ipaddr

	return nil
}

// IPAddr returns the IP address of the target host.
func (p *Pinger) IPAddr() *net.IPAddr {
	return p.ipaddr
}

// SetAddr resolves and sets the ip address of the target host, addr can be a
// DNS name like "www.google.com" or IP like "127.0.0.1".
func (p *Pinger) SetAddr(addr string) error {
	oldAddr := p.addr
	p.addr = addr
	err := p.Resolve()
	if err != nil {
		p.addr = oldAddr
		return err
	}

	return nil
}

// SetNetwork allows configuration of DNS resolution.
// * "ip" will automatically select IPv4 or IPv6.
// * "ip4" will select IPv4.
// * "ip6" will select IPv6.
func (p *Pinger) SetNetwork(n string) {
	switch n {
	case "ip4":
		p.network = "ip4"
	case "ip6":
		p.network = "ip6"
	default:
		p.network = "ip"
	}
}

// Addr returns the string ip address of the target host.
func (p *Pinger) Addr() string {
	return p.addr
}

// SetPrivileged sets the type of ping pinger will send.
// false means pinger will send an "unprivileged" UDP ping.
// true means pinger will send a "privileged" raw ICMP ping.
// NOTE: setting to true requires that it be run with super-user privileges.
func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.protocol = "icmp"
	} else {
		p.protocol = "udp"
	}
}

// Privileged returns whether pinger is running in privileged mode.
func (p *Pinger) Privileged() bool {
	return p.protocol == "icmp"
}

// Statistics returns the statistics of the pinger. This can be run while the
// pinger is running or after it is finished. OnFinish calls this function to
// get its finished statistics.
func (p *Pinger) Statistics() *Statistics {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()
	sent := p.PacketsSent
	loss := float64(sent-p.PacketsRecv) / float64(sent) * 100
	s := Statistics{
		PacketsSent:           sent,
		PacketsRecv:           p.PacketsRecv,
		PacketsRecvDuplicates: p.PacketsRecvDuplicates,
		PacketLoss:            loss,
		Rtts:                  p.rtts,
		Addr:                  p.addr,
		IPAddr:                p.ipaddr,
		MaxRtt:                p.maxRtt,
		MinRtt:                p.minRtt,
		AvgRtt:                p.avgRtt,
		StdDevRtt:             p.stdDevRtt,
	}
	return &s
}

func (p *Pinger) listen(netProto string) (*icmp.PacketConn, error) {
	conn, err := icmp.ListenPacket(netProto, p.Source)
	if err != nil {
		p.Stop()
		return nil, err
	}
	return conn, nil
}

func (p *Pinger) sendICMP(conn *icmp.PacketConn) error {
	var typ icmp.Type
	if p.ipv4 {
		typ = ipv4.ICMPTypeEcho
	} else {
		typ = ipv6.ICMPTypeEchoRequest
	}

	var dst net.Addr = p.ipaddr
	if p.protocol == "udp" {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}

	t := append(timeToBytes(time.Now()), uintToBytes(p.Tracker)...)
	if remainSize := p.Size - timeSliceLength - trackerLength; remainSize > 0 {
		t = append(t, bytes.Repeat([]byte{1}, remainSize)...)
	}

	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.sequence,
		Data: t,
	}

	msg := &icmp.Message{
		Type: typ,
		Code: 0,
		Body: body,
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	for {
		if _, err := conn.WriteTo(msgBytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		handler := p.OnSend
		if handler != nil {
			outPkt := &Packet{
				Nbytes: len(msgBytes),
				IPAddr: p.ipaddr,
				Addr:   p.addr,
				Seq:    p.sequence,
			}
			handler(outPkt)
		}
		// mark this sequence as in-flight
		p.awaitingSequences[p.sequence] = struct{}{}
		p.PacketsSent++
		p.sequence++
		break
	}

	return nil
}

func (p *Pinger) recvICMP(
	conn *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) error {
	defer wg.Done()

	// Start by waiting for 50 ??s and increase to a possible maximum of ~ 100 ms.
	expBackoff := newExpBackoff(50*time.Microsecond, 11)
	delay := expBackoff.Get()

	for {
		select {
		case <-p.done:
			return nil
		default:
			// ICMP messages have an 8-byte header.
			bytes := make([]byte, p.getMessageLength())
			if err := conn.SetReadDeadline(time.Now().Add(delay)); err != nil {
				return err
			}
			var n, ttl int
			var err error
			if p.ipv4 {
				var cm *ipv4.ControlMessage
				n, cm, _, err = conn.IPv4PacketConn().ReadFrom(bytes)
				if cm != nil {
					ttl = cm.TTL
				}
			} else {
				var cm *ipv6.ControlMessage
				n, cm, _, err = conn.IPv6PacketConn().ReadFrom(bytes)
				if cm != nil {
					ttl = cm.HopLimit
				}
			}
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						delay = expBackoff.Get()
						continue
					} else {
						p.Stop()
						return err
					}
				}
			}

			select {
			case <-p.done:
				return nil
			case recv <- &packet{bytes: bytes, nbytes: n, ttl: ttl}:
			}
		}
	}
}

func (p *Pinger) processPacket(recv *packet) error {
	receivedAt := time.Now()
	var proto int
	if p.ipv4 {
		proto = protocolICMP
	} else {
		proto = protocolIPv6ICMP
	}

	var m *icmp.Message
	var err error
	if m, err = icmp.ParseMessage(proto, recv.bytes); err != nil {
		return fmt.Errorf("error parsing icmp message: %w", err)
	}

	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	inPkt := &Packet{
		Nbytes: recv.nbytes,
		IPAddr: p.ipaddr,
		Addr:   p.addr,
		Ttl:    recv.ttl,
	}

	switch pkt := m.Body.(type) {
	case *icmp.Echo:
		if !p.matchID(pkt.ID) {
			return nil
		}
		if len(pkt.Data) < timeSliceLength+trackerLength {
			return fmt.Errorf("insufficient data received; got: %d %v", len(pkt.Data), pkt.Data)
		}

		tracker := bytesToUint(pkt.Data[timeSliceLength:])
		timestamp := bytesToTime(pkt.Data[:timeSliceLength])

		if tracker != p.Tracker {
			return nil
		}

		inPkt.Rtt = receivedAt.Sub(timestamp)
		inPkt.Seq = pkt.Seq
		// If we've already received this sequence, ignore it.
		if _, inflight := p.awaitingSequences[pkt.Seq]; !inflight {
			p.PacketsRecvDuplicates++
			if p.OnDuplicateRecv != nil {
				p.OnDuplicateRecv(inPkt)
			}
			return nil
		}
		// Remove it from the list of sequences we're waiting for so we don't get duplicates.
		delete(p.awaitingSequences, pkt.Seq)
		p.updateStatistics(inPkt)
	default:
		// Very bad, not sure how this can happen
		return fmt.Errorf("invalid ICMP echo reply; type: '%T', '%v'", pkt, pkt)
	}

	handler := p.OnRecv
	if handler != nil {
		handler(inPkt)
	}

	return nil
}

// Run runs the pinger. This is a blocking function that will exit when it's
// done. If Count or Interval are not specified, it will continuously until
// it is interrupted.
func (p *Pinger) Run() error {
	logger := p.logger
	if logger == nil {
		logger = NoopLogger{}
	}

	var conn *icmp.PacketConn
	var err error
	if p.ipaddr == nil {
		err = p.Resolve()
	}
	if err != nil {
		return err
	}
	if p.ipv4 {
		if conn, err = p.listen(ipv4Proto[p.protocol]); err != nil {
			return err
		}
		if err = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); runtime.GOOS != "windows" && err != nil {
			return err
		}
	} else {
		if conn, err = p.listen(ipv6Proto[p.protocol]); err != nil {
			return err
		}
		if err = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true); runtime.GOOS != "windows" && err != nil {
			return err
		}
	}
	defer conn.Close()
	defer p.finish()

	var wg sync.WaitGroup
	recv := make(chan *packet, 5)
	defer close(recv)
	wg.Add(1)
	//nolint:errcheck
	go p.recvICMP(conn, recv, &wg)

	if handler := p.OnSetup; handler != nil {
		handler()
	}

	timeout := time.NewTicker(p.Timeout)
	interval := time.NewTicker(p.Interval)
	defer func() {
		p.Stop()
		timeout.Stop()
		interval.Stop()
		wg.Wait()
	}()

	err = p.sendICMP(conn)
	if err != nil {
		return err
	}

	for {
		select {
		case <-p.done:
			return nil
		case <-timeout.C:
			return nil
		case r := <-recv:
			err := p.processPacket(r)
			if err != nil {
				logger.Fatalf("processing received packet: %s", err)
			}
		case <-interval.C:
			if p.Count > 0 && p.PacketsSent >= p.Count {
				interval.Stop()
				continue
			}
			err = p.sendICMP(conn)
			if err != nil {
				logger.Fatalf("sending packet: %s", err)
			}
		}
		if p.Count > 0 && p.PacketsRecv >= p.Count {
			return nil
		}
	}
}

func (p *Pinger) finish() {
	handler := p.OnFinish
	if handler != nil {
		s := p.Statistics()
		handler(s)
	}
}

func (p *Pinger) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	open := true
	select {
	case _, open = <-p.done:
	default:
	}

	if open {
		close(p.done)
	}
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

func bytesToUint(b []byte) uint64 {
	return uint64(binary.BigEndian.Uint64(b))
}

func uintToBytes(tracker uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, tracker)
	return b
}

var seed int64 = time.Now().UnixNano()

// getSeed returns a goroutine-safe unique seed
func getSeed() int64 {
	return atomic.AddInt64(&seed, 1)
}

type expBackoff struct {
	baseDelay time.Duration
	maxExp    int64
	c         int64
}

func (b *expBackoff) Get() time.Duration {
	if b.c < b.maxExp {
		b.c++
	}

	return b.baseDelay * time.Duration(rand.Int63n(1<<b.c))
}

func newExpBackoff(baseDelay time.Duration, maxExp int64) expBackoff {
	return expBackoff{baseDelay: baseDelay, maxExp: maxExp}
}
