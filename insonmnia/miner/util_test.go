package miner

import (
	"net"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortableIPs(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2001:db8::68"),
		net.ParseIP("46.148.198.133"),
		net.ParseIP("fd21:f7bb:61b8:9e37:0:0:0:1"),
		net.ParseIP("192.168.70.17"),
	}
	sortedIPs := []net.IP{
		net.ParseIP("2001:db8::68"),
		net.ParseIP("46.148.198.133"),
		net.ParseIP("fd21:f7bb:61b8:9e37:0:0:0:1"),
		net.ParseIP("192.168.70.17"),
	}
	sort.Sort(sortableIPs(ips))
	assert.Equal(t, ips, sortedIPs)
}
