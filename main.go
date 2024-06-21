package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/joho/godotenv"
	"github.com/perbu/dhcp-detective/dhcp"
	"github.com/perbu/dhcp-detective/slackbot"
	"github.com/perbu/dhcp-detective/snoop"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	_ = godotenv.Load()
	err := run(ctx, os.Stdout, os.Stderr, os.Args, os.Environ())
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

}

func run(octx context.Context, stdout, stderr *os.File, args []string, env []string) error {
	ctx, cancel := context.WithCancel(octx)
	defer cancel()
	// -i interface, required
	// -d debug
	interfaceFlag := flag.String("i", "", "Interface to listen on")
	debugFlag := flag.Bool("d", false, "Enable debug output")
	interval := flag.Duration("interval", 5*time.Minute, "Interval between DHCP discoveries")
	if err := flag.CommandLine.Parse(args[1:]); err != nil {
		return fmt.Errorf("flag.CommandLine.Parse: %w", err)
	}

	// check that interval is at least 10 seconds:
	if *interval < 10*time.Second {
		return fmt.Errorf("interval must be at least 10 seconds, come on! (was %s)", *interval)
	}
	if *interfaceFlag == "" {
		return fmt.Errorf("please provide the interface to listen on using the -i flag")
	}
	level := slog.LevelInfo
	if *debugFlag {
		level = slog.LevelDebug
	}
	logHandler := slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})
	logger := slog.New(logHandler)

	// set up the slack bot:
	slackToken, ok := getEnvString(env, "SLACK_TOKEN")
	if !ok {
		return fmt.Errorf("please set the SLACK_TOKEN environment variable")
	}

	slackChannel, ok := getEnvString(env, "SLACK_CHANNEL")
	if !ok {
		return fmt.Errorf("please set the SLACK_CHANNEL environment variable")

	}
	slackBot, err := slackbot.New(slackToken, slackChannel, logger, *debugFlag)
	if err != nil {
		return fmt.Errorf("slackbot.New: %w", err)
	}

	logger.Debug("slackbot initialized")

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "[unknown]"
	}
	err = slackBot.Say(fmt.Sprintf("Starting DHCP detective on %s", hostname))
	if err != nil {
		return fmt.Errorf("slackBot.Say: %w", err)
	}

	// start the DHCP filter:
	dhcpChan, err := snoop.DHCPOffers(ctx, *interfaceFlag)
	if err != nil {
		return fmt.Errorf("snoop.DHCPOffers: %w", err)
	}
	logger.Debug("DHCP snoop initialized")

	prober, err := dhcp.New(*interfaceFlag, logger)
	if err != nil {
		return fmt.Errorf("dhcp.New: %w", err)
	}
	go func() {
		time.Sleep(5 * time.Second)
		for {
			logger.Debug("Sending DHCP discovery")
			err := prober.Disco()
			if err != nil {
				_, _ = fmt.Fprintf(stderr, "prober.Disco: %v\n", err)
				logger.Error("prober.Disco failed, cancelling context", "error", err)
				cancel()
			}
			time.Sleep(*interval)
		}
	}()

	lastAlert := time.Time{}
	logger.Info("Waiting for first DHCP offer")
	firstPacket := <-dhcpChan
	acceptedMAC, ok := extractMac(firstPacket)
	if !ok {
		return fmt.Errorf("could not extract MAC address from first DHCP offer")
	}
	if err := slackBot.Say(fmt.Sprintf("First DHCP offer received, assuming this DHCP server is kosher: %s", acceptedMAC.String())); err != nil {
		return fmt.Errorf("slackBot.Say: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled")
		case packet, ok := <-dhcpChan:
			if !ok {
				return fmt.Errorf("dhcpChan closed")
			}
			mac, ok := extractMac(packet)
			if !ok {
				logger.Warn("packet does not have an Ethernet layer", "packet", packet)
				continue
			}
			logger.Debug("Got DHCP offer", "packet", packet, "mac", mac.String())
			if time.Since(lastAlert) < 10*time.Minute {
				logger.Info("Ignoring packet, too soon since last alert")
				continue
			}
			if mac.String() == acceptedMAC.String() {
				logger.Debug("Ignoring packet, MAC address is the accepted one")
				continue
			}
			lastAlert = time.Now()
			err := slackBot.Say(fmt.Sprintf("Rogue DHCP server detected: %s", mac.String()))
			if err != nil {
				return fmt.Errorf("slackBot.Say: %w", err)
			}
		}
		return nil
	}
}

func extractMac(packet gopacket.Packet) (net.HardwareAddr, bool) {
	eth, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		return net.HardwareAddr{}, false
	}
	return eth.SrcMAC, true
}

func getEnvString(env []string, key string) (string, bool) {
	for _, e := range env {
		if len(e) < len(key)+1 {
			continue
		}
		if key == e[:len(key)] {
			return e[len(key)+1:], true
		}
	}
	return "", false
}

func packetToString(packet gopacket.Packet) string {
	// Get the Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return "(no ethernet layer in packet)"
	}
	ethernet, ok := ethernetLayer.(*layers.Ethernet)
	if !ok {
		return "Ethernet layer type assertion failed"
	}
	return fmt.Sprintf("Source MAC: %s", ethernet.SrcMAC)
}
