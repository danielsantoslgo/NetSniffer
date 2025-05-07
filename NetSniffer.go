package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// PacketSummary holds simplified packet info for JSON output
type PacketSummary struct {
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    string `json:"protocol"`
	Length      int    `json:"length"`
}

func main() {
	// List all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Available network interfaces:")
	for i, device := range devices {
		fmt.Printf("[%d] Name: %s, Description: %s\n", i, device.Name, device.Description)
	}

	var choice int
	fmt.Print("\nSelect the interface to sniff (enter number): ")
	fmt.Scanf("%d", &choice)

	if choice < 0 || choice >= len(devices) {
		log.Fatalf("Invalid choice: %d", choice)
	}

	device := devices[choice].Name
	fmt.Printf("\nStarting capture on interface: %s\n", device)

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Apply BPF filter (optional: capture only TCP packets)
	filter := "tcp"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}
	fmt.Printf("BPF filter applied: %s\n", filter)

	// Create pcap file to save packets
	pcapFile, err := os.Create("capture.pcap")
	if err != nil {
		log.Fatalf("Error creating pcap file: %v", err)
	}
	defer pcapFile.Close()
	pcapWriter := pcapgo.NewWriter(pcapFile)
	err = pcapWriter.WriteFileHeader(1600, handle.LinkType())
	if err != nil {
		log.Fatalf("Error writing pcap file header: %v", err)
	}
	fmt.Println("Packets will be saved to capture.pcap")

	// Handle SIGINT to exit cleanly
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		fmt.Println("\nCapture interrupted. Exiting...")
		handle.Close()
		pcapFile.Close()
		os.Exit(0)
	}()

	// Use packet source to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Write raw packet to .pcap file
		err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			log.Printf("Error writing packet to file: %v", err)
		}

		// Print simplified JSON
		networkLayer := packet.NetworkLayer()
		transportLayer := packet.TransportLayer()
		if networkLayer != nil && transportLayer != nil {
			summary := PacketSummary{
				Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
				SrcIP:     networkLayer.NetworkFlow().Src().String(),
				DstIP:     networkLayer.NetworkFlow().Dst().String(),
				Protocol:  transportLayer.LayerType().String(),
				Length:    len(packet.Data()),
			}
			jsonData, _ := json.MarshalIndent(summary, "", "  ")
			fmt.Println(string(jsonData))
		}
	}
}
