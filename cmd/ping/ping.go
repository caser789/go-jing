package main

import (
	"flag"
	"fmt"
	ping "github.com/caser789/go-jing"
	"time"
)

var usage = `
Usage:

	ping [-c count] [-i interval] [-t timeout] host

Examples:

	# ping google continuously
	ping www.google.com

	# ping google 5 times
	ping -c 5 www.google.com

	# ping google 5 times at 500ms interval
	ping -c 5 -i 500ms www.google.com

	# ping google for 10 seconds
	ping -t 10s www.google.com
`

func main() {
	timeout := flag.Duration("t", time.Second*100000, "")
	interval := flag.Duration("i", time.Second, "")
	count := flag.Int("c", -1, "")
	privileged := flag.Bool("privileged", false, "")
	flag.Usage = func() {
		fmt.Printf(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}

	host := flag.Arg(0)
	pinger, err := ping.NewPinger(host)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	pinger.OnRecv = func(pkt *ping.Packet) {
		fmt.Printf(
			"%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt,
		)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	pinger.Count = *count
	pinger.Interval = *interval
	pinger.Timeout = *timeout
	pinger.SetPrivileged(*privileged)

	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	pinger.Run()
}