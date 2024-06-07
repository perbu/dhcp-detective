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
	"os"
	"os/signal"
	"syscall"
	"time"
)

const sayHello = false

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

func run(ctx context.Context, stdout, stderr *os.File, args []string, env []string) error {
	// handle arguments, both are required:
	// -i interface
	// -a allowed MAC address
	interfaceFlag := flag.String("i", "", "Interface to listen on")
	macAddressFlag := flag.String("a", "", "Allowed MAC address")
	flag.CommandLine.Parse(args[1:])

	if *interfaceFlag == "" {
		return fmt.Errorf("please provide the interface to listen on using the -i flag")
	}
	if *macAddressFlag == "" {
		return fmt.Errorf("please provide the allowed MAC address using the -a flag")
	}
	fmt.Printf("Interface: %s\n", *interfaceFlag)
	fmt.Printf("Allowed MAC address: %s\n", *macAddressFlag)

	// set up the slack bot:
	slackToken, ok := getEnvString(env, "SLACK_TOKEN")
	if !ok {
		return fmt.Errorf("please set the SLACK_TOKEN environment variable")
	}

	slackChannel, ok := getEnvString(env, "SLACK_CHANNEL")
	if !ok {
		return fmt.Errorf("please set the SLACK_CHANNEL environment variable")

	}
	slackBot, err := slackbot.New(slackToken, slackChannel)
	if err != nil {
		return fmt.Errorf("slackbot.New: %w", err)
	}

	if sayHello {
		hostname, _ := os.Hostname()
		err = slackBot.Say(fmt.Sprintf("Starting DHCP detective on %s", hostname))
		if err != nil {
			return fmt.Errorf("slackBot.Say: %w", err)
		}
	}

	// start the DHCP filter:
	dhcpChan, err := snoop.DHCPOffers(ctx, *interfaceFlag, *macAddressFlag)
	if err != nil {
		return fmt.Errorf("snoop.DHCPOffers: %w", err)
	}
	// start the prober, this will send out messages every minute

	prober, err := dhcp.New(*interfaceFlag)
	if err != nil {
		return fmt.Errorf("dhcp.New: %w", err)
	}

	go func() {
		time.Sleep(5 * time.Second)
		for {
			err := prober.Disco()
			if err != nil {
				fmt.Fprintf(stderr, "prober.Disco: %v\n", err)
				panic("prober.Disco failed")
			}
			time.Sleep(time.Minute)
		}
	}()

	lastAlert := time.Time{}
	fmt.Println("Listening for rogue DHCP servers...")
	for packet := range dhcpChan {
		str := packetToString(packet)
		fmt.Printf("Got rouge DHCP packet: %s\n", str)
		// only alert once every 10 minutes
		if time.Since(lastAlert) < 10*time.Minute {
			continue
		}
		lastAlert = time.Now()
		err := slackBot.Say(fmt.Sprintf("Rogue DHCP server detected: %s", str))
		if err != nil {
			return fmt.Errorf("slackBot.Say: %w", err)
		}
	}
	return nil
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
