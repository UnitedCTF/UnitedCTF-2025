package protoaddr

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ProtoAddr struct {
	Protocol string
	IP       string
	Port     uint32
}

func NewAddr(protocol string, ip string, port uint32) *ProtoAddr {
	return &ProtoAddr{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
	}
}

func ParseAddr(addr string) (*ProtoAddr, error) {
	parts := strings.Split(addr, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid address format")
	}

	ip, port, err := net.SplitHostPort(parts[1])
	if err != nil {
		return nil, err
	}

	portInt, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return nil, err
	}
	return NewAddr(parts[0], ip, uint32(portInt)), nil
}

func (a *ProtoAddr) Address() string {
	return net.JoinHostPort(a.IP, strconv.Itoa(int(a.Port)))
}

func (a *ProtoAddr) String() string {
	return fmt.Sprintf("%s://%s", a.Protocol, net.JoinHostPort(a.IP, strconv.Itoa(int(a.Port))))
}
