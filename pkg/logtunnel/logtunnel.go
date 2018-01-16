package logtunnel

import (
	"io"
	"net"
	"log"
	"time"
	
	"golang.org/x/crypto/ssh"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type ForwardData struct {
	DestinationHost string
	DestinationPort uint32
	SourceHost string
	SourcePort uint32
}

type logTunnel struct {
	channel ssh.Channel
	writer  io.WriteCloser
	pcapwriter *pcapgo.Writer
	forwarddata ForwardData
	destinationHost net.IP
	sourceHost net.IP
	destinationPort uint32
	sourcePort uint32
}

func New(channel ssh.Channel, writer io.WriteCloser, d ForwardData) *logTunnel {
	pcapwriter := pcapgo.NewWriter(writer)
	pcapwriter.WriteFileHeader(65536, layers.LinkTypeIPv4)
	return &logTunnel{
		channel: channel,
		writer:  writer,
		pcapwriter: pcapwriter,
		forwarddata: d,	
	}
}

func (l *logTunnel) Read(data []byte) (int, error) {
	return l.Read(data)
}

func (l *logTunnel) Write(data []byte) (int, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	destinationHost := net.ParseIP(l.forwarddata.DestinationHost)
	sourceHost := net.ParseIP(l.forwarddata.SourceHost)
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(l.forwarddata.SourcePort),
		DstPort: layers.TCPPort(l.forwarddata.DestinationPort),
	}
	switch {
	case len(destinationHost) == 4 && len(sourceHost) == 4:
		ipLayer := &layers.IPv4{
			SrcIP: sourceHost,
			DstIP: destinationHost,
		}
		gopacket.SerializeLayers(buf, opts,
			ipLayer,
			tcpLayer,
			gopacket.Payload(data))
		data := buf.Bytes()
		l.pcapwriter.WritePacket(
			gopacket.CaptureInfo{
				Timestamp: time.Now(),
				CaptureLength: len(data),
				Length: len(data),
				InterfaceIndex: 0}, data)
		
	case len(destinationHost) == 16 && len(sourceHost) == 16:
		ipLayer := &layers.IPv6{
			SrcIP: sourceHost,
			DstIP: destinationHost,
		}
		gopacket.SerializeLayers(buf, opts,
			ipLayer,
			tcpLayer,
			gopacket.Payload(data))
		data := buf.Bytes()
		l.pcapwriter.WritePacket(
			gopacket.CaptureInfo{
				Timestamp: time.Now(),
				CaptureLength: len(data),
				Length: len(data),
				InterfaceIndex: 0}, data)
	default:
		log.Fatalf("Invalid tunnel host")
	}
	
	return l.channel.Write(data)
}

func (l *logTunnel) Close() error {
	l.writer.Close()
	return l.channel.Close()
}
