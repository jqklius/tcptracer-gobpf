package main

import (
    "C"
    "bytes"
    "encoding/binary"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/signal"
    "unsafe"
    bpf "github.com/iovisor/gobpf/bcc"
)

type tcpIpv4Event struct {
    TSns        uint64 // Current TimeStamp in nanoseconds
    TcpType     uint32
    Pid         uint32
    Comm        [16]byte // TASK_COMM_LEN=16
    IpVer       uint8
    Padding     [3]byte
    Saddr       uint32
    Daddr       uint32
    Sport       uint16
    Dport       uint16
    Netns       uint32
}

// https://grokbase.com/t/gg/golang-nuts/135a3a02ar/go-nuts-simpler-int-ip-unpacking#20130510t4i5trr2w2pemcryxagru2lcoq
func IpIntToByte(ip uint32) net.IP {
    result := make(net.IP, 4)
            result[0] = byte(ip)
            result[1] = byte(ip >> 8)
            result[2] = byte(ip >> 16)
            result[3] = byte(ip >> 24)
    return result
}

func TcpTypeIntToString(TcpType uint32) string {
    result := "unknown"
    if TcpType == 1 {
        result = "connect"
    } else if TcpType == 2 {
        result = "accept"
    } else if TcpType == 3 {
        result = "close"
    }
    return result
}

func main() {
    // https://golangcode.com/read-a-files-contents/
    // https://stackoverflow.com/questions/13514184/how-can-i-read-a-whole-file-into-a-string-variable
    sourceByte, err := ioutil.ReadFile("tcptracer.c")
    if err != nil {
        log.Fatal(err)
    }
    source := string(sourceByte)

    // https://github.com/iovisor/gobpf/blob/master/bcc/module.go#L115
    // NewModule(code string, cflags []string) asynchronously compiles the code, generates a new BPF module and returns it.
    m := bpf.NewModule(source, []string{})
    defer m.Close()

    // https://github.com/iovisor/gobpf/blob/master/bcc/module.go#L176
    // LoadKprobe(name string) loads a program of type BPF_PROG_TYPE_KPROBE.
    kprobe, err := m.LoadKprobe("trace_connect_v4_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_entry: %s\n", err)
        os.Exit(1)
    }
    // https://github.com/iovisor/gobpf/blob/master/bcc/module.go#L273
    // AttachKprobe(fnName string, fd int, maxActive int) attaches a kprobe fd to a function.
    m.AttachKprobe("tcp_v4_connect", kprobe, 0)

    kprobe, err = m.LoadKprobe("trace_connect_v4_return")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_connect_v4_return: %s\n", err)
        os.Exit(1)
    }
    m.AttachKretprobe("tcp_v4_connect", kprobe, 0)

    kprobe, err = m.LoadKprobe("trace_tcp_set_state_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_tcp_set_state_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_set_state", kprobe, 0)
    // TCP Connect (need above 3 attach probe)

    // TCP Close
    kprobe, err = m.LoadKprobe("trace_close_entry")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_close_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKprobe("tcp_close", kprobe, 0)

    // TCP Accept
    kprobe, err = m.LoadKprobe("trace_accept_return")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load trace_close_entry: %s\n", err)
        os.Exit(1)
    }
    m.AttachKretprobe("inet_csk_accept", kprobe, 0)

    // https://github.com/iovisor/gobpf/blob/master/bcc/table.go#L42
    // NewTable(id C.size_t, module *Module) returns a refernce to a BPF table.
    table := bpf.NewTable(m.TableId("tcp_ipv4_event"), m)
    channel := make(chan []byte)

    // https://github.com/iovisor/gobpf/blob/master/bcc/perf.go#L110
    // InitPerfMap(table *Table, receiverChan chan []byte) initializes a perf map with a receiver channel.
    perfMap, err := bpf.InitPerfMap(table, channel)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
        os.Exit(1)
    }

    // Use "chan" for catch signal.
    sig := make(chan os.Signal, 1)

    // registers the given channel to receive notifications of the specified signals.
    signal.Notify(sig, os.Interrupt, os.Kill)

    // This goroutine executes a blocking receive for signals.
    go receiveChan(channel)

    // Start to poll the perf map reader and send back event data over the connected channel.
    perfMap.Start()

    <-sig

    // Stop to poll the perf map readers after a maximum of 500ms.
    perfMap.Stop()

    fmt.Printf("Goodbye.\n")
}

func receiveChan(channel chan []byte) {
    fmt.Printf("Hello, I'm ready.\n")
    var event tcpIpv4Event
    for {
        data := <-channel // waiting here

        // https://github.com/iovisor/gobpf/blob/master/bcc/perf.go#L94
        // bpf.GetHostByteOrder() == binary.LittleEndian || binary.BigEndian
        err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &event)
        if err != nil {
            fmt.Printf("failed to decode received data: %s\n", err)
            continue
        }

        fmt.Printf("-------------------\n")
        log.Print() // Print time
        fmt.Printf("TSns   : %d \n", event.TSns)
        fmt.Printf("Type   : %s \n", TcpTypeIntToString(event.TcpType))
        fmt.Printf("PID    : %d \n", event.Pid)
        Comm := (*C.char)(unsafe.Pointer(&event.Comm))
        fmt.Printf("COMM   : %s \n", C.GoString(Comm))
        fmt.Printf("IP     : IPv%d \n", event.IpVer)
        fmt.Printf("SADDR  : %s \n", IpIntToByte(event.Saddr))
        fmt.Printf("DADDR  : %s \n", IpIntToByte(event.Daddr))
        fmt.Printf("SPORT  : %d \n", event.Sport)
        fmt.Printf("DPORT  : %d \n", event.Dport)
        fmt.Printf("NETNS  : %d \n", event.Netns)
    }
}