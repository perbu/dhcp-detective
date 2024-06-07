package dhcp

import (
	"fmt"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/interfaces"
	"log/slog"
	"net"
	"time"
)

const (
	// defaultMac = "DE:AD:BE:EF:C0:DE"
	defaultMac = "50:eb:f6:57:2d:46"
)

type State struct {
	previous string
	ts       time.Time
	iface    *net.Interface
	conn     net.PacketConn // to be filled by a NewRawUDPConn call
	c        *nclient4.Client
	logger   *slog.Logger
}

func New(ifaceName string, logger *slog.Logger) (*State, error) {
	var err error
	s := &State{
		logger: logger,
	}
	s.iface, err = getInterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("getInterfaceByName: %w", err)
	}
	s.conn, err = nclient4.NewRawUDPConn(s.iface.Name, 68)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket: %w", err)
	}
	logger.Debug("raw socket initialized", "iface", s.iface.Name)
	return s, nil
}

// Disco sends a DHCP discover message
func (s *State) Disco() error {
	message, err := dhcpv4.NewDiscovery(s.iface.HardwareAddr)
	if err != nil {
		return fmt.Errorf("dhcpv4.NewDiscovery: %w", err)
	}
	_, err = s.conn.WriteTo(message.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: 67})
	if err != nil {
		return fmt.Errorf("conn.WriteTo: %w", err)
	}
	return nil
}

func getInterfaceByName(name string) (*net.Interface, error) {
	faces, err := interfaces.GetNonLoopbackInterfaces()
	if err != nil {
		return nil, fmt.Errorf("interfaces.GetNonLoopbackInterfaces: %w", err)
	}
	if len(faces) == 0 {
		return nil, fmt.Errorf("no non-loopback interfaces found")
	}
	for _, face := range faces {
		if face.Name == name {
			return &face, nil
		}
	}
	return nil, fmt.Errorf("interface '%s' not found", name)
}
