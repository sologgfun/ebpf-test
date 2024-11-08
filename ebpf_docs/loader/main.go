package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	spec, err := ebpf.LoadCollectionSpec("loader_bpfel.o") // 确保文件路径正确
	if err != nil {
		log.Fatalf("Failed to load collection spec: %v", err)
	}

	objs := struct {
		Programs struct {
			MonitorTraffic *ebpf.Program `ebpf:"monitor_traffic"`
		}
		Maps struct {
			TrafficMap *ebpf.Map `ebpf:"traffic_map"`
		}
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign objects: %v", err)
	}
	defer objs.Programs.MonitorTraffic.Close()
	defer objs.Maps.TrafficMap.Close()

	// Attach XDP program to the network interface
	ifname := "eth0" // 替换为你的网络接口名称
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %v", ifname, err)
	}

	// 尝试使用 XDPDriverMode
	linkInstance, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Programs.MonitorTraffic,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("Failed to attach XDP program in driver mode: %v", err)
		// 如果 XDPDriverMode 失败，尝试使用 XDPGenericMode
		linkInstance, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.Programs.MonitorTraffic,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("Failed to attach XDP program in generic mode: %v", err)
		}
	}
	defer linkInstance.Close()

	rd, err := perf.NewReader(objs.Maps.TrafficMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("Listening for traffic events...")

	// Set up signal handling to gracefully exit
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Fatalf("Failed to read from perf reader: %v", err)
			}

			if record.LostSamples != 0 {
				fmt.Printf("Lost %d samples\n", record.LostSamples)
				continue
			}

			var event TrafficEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Fatalf("Failed to decode received data: %v", err)
			}

			srcIP := net.IP(event.SrcIP[:])
			dstIP := net.IP(event.DstIP[:])
			fmt.Printf("Traffic event: SrcIP: %s, SrcPort: %d, DstIP: %s, DstPort: %d, Bytes: %d\n",
				srcIP, event.SrcPort, dstIP, event.DstPort, event.Bytes)
		}
	}()

	<-stop
	fmt.Println("Received signal, exiting...")
}

type TrafficEvent struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Bytes   uint64
}
