package snoop

import (
	"context"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

type PacketChan <-chan gopacket.Packet

// Snoop captures packets from the network interface iface that match the filter
// expression filter. It returns a channel that will deliver the packets it captures.
// The caller must cancel the context to stop capturing packets.
func Snoop(ctx context.Context, iface, filter string) (PacketChan, error) {
	handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive(%s): %w", iface, err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("handle.SetBPFFilter(%s): %w", filter, err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := make(chan gopacket.Packet, 100)
	ichan := packetSource.PacketsCtx(ctx)
	go func() {
		defer fmt.Println("Snooper ending")
		for {
			select {
			case <-ctx.Done():
				fmt.Println("context cancelled, closing handle and channel. this may take some time.")
				handle.Close()
				fmt.Println("pcap handle closed")
				close(pchan)
				return
			case packet := <-ichan:
				pchan <- packet
			}
		}
	}()
	return pchan, nil
}

// DHCPFilter takes a allowed MAC address and returns a channel that will deliver
// only DHCP packet that are NOT coming from the allowed MAC address. So the packets
// will be coming from rogue DHCP servers.
func DHCPFilter(ctx context.Context, iface, allowed string) (PacketChan, error) {
	defer fmt.Println("DHCPFilter ending")
	filter := fmt.Sprintf("udp and port 67 and port 68 and not ether src %s", allowed)
	return Snoop(ctx, iface, filter)
}
