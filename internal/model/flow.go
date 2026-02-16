package model

import (
	"fmt"
	"net"
	"time"
)

// Flow represents a unified flow record decoded from any NetFlow/IPFIX version.
type Flow struct {
	Timestamp    time.Time
	SrcAddr      net.IP
	DstAddr      net.IP
	SrcPort      uint16
	DstPort      uint16
	Protocol     uint8 // TCP=6, UDP=17, ICMP=1, etc.
	Bytes        uint64
	Packets      uint64
	TCPFlags     uint8
	ToS          uint8
	InputIface   uint32
	OutputIface  uint32
	SrcAS        uint32
	DstAS        uint32
	Duration     time.Duration
	ExporterIP   net.IP // which device sent this flow
	AppProto     string // L7 application protocol (e.g. "HTTP", "DNS")
	AppCat       string // traffic category (e.g. "Web", "Email")
}

// Classify populates AppProto and AppCat using port-based heuristic detection.
// It should be called after all other flow fields have been set.
func (f *Flow) Classify() {
	f.AppProto = AppProtocol(f.Protocol, f.SrcPort, f.DstPort)
	f.AppCat = AppCategory(f.AppProto)
}

// ProtocolName returns a human-readable name for common IP protocol numbers.
func ProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto(%d)", proto)
	}
}

// String returns a brief summary of the flow record.
func (f Flow) String() string {
	return fmt.Sprintf("%s %s:%d → %s:%d %s %d bytes %d pkts",
		f.Timestamp.Format(time.RFC3339),
		f.SrcAddr, f.SrcPort,
		f.DstAddr, f.DstPort,
		ProtocolName(f.Protocol),
		f.Bytes, f.Packets,
	)
}

// SafeIPString converts a net.IP to string, returning "0.0.0.0" for nil IPs.
func SafeIPString(ip net.IP) string {
	if ip == nil {
		return "0.0.0.0"
	}
	return ip.String()
}

// AppProtocol returns a human-readable Layer-7 application protocol name
// based on well-known port numbers and the L4 protocol. When the port is
// not recognised, it returns "Other".
func AppProtocol(proto uint8, srcPort, dstPort uint16) string {
	// Use the lower (well-known) port as the indicator.
	port := dstPort
	if srcPort < dstPort {
		port = srcPort
	}

	switch {
	// DNS
	case port == 53:
		return "DNS"
	// HTTP
	case port == 80 || port == 8080 || port == 8000:
		return "HTTP"
	// HTTPS / TLS
	case port == 443 || port == 8443:
		return "HTTPS"
	// SSH
	case port == 22:
		return "SSH"
	// FTP
	case port == 20 || port == 21:
		return "FTP"
	// SMTP
	case port == 25 || port == 587 || port == 465:
		return "SMTP"
	// IMAP
	case port == 143 || port == 993:
		return "IMAP"
	// POP3
	case port == 110 || port == 995:
		return "POP3"
	// Telnet
	case port == 23:
		return "Telnet"
	// RDP
	case port == 3389:
		return "RDP"
	// MySQL
	case port == 3306:
		return "MySQL"
	// PostgreSQL
	case port == 5432:
		return "PostgreSQL"
	// Redis
	case port == 6379:
		return "Redis"
	// MongoDB
	case port == 27017:
		return "MongoDB"
	// NTP
	case port == 123:
		return "NTP"
	// SNMP
	case port == 161 || port == 162:
		return "SNMP"
	// LDAP
	case port == 389 || port == 636:
		return "LDAP"
	// Syslog
	case port == 514:
		return "Syslog"
	// DHCP
	case port == 67 || port == 68:
		return "DHCP"
	// NetFlow / IPFIX
	case port == 2055 || port == 4739 || port == 9996:
		return "NetFlow"
	// SMB
	case port == 445 || port == 139:
		return "SMB"
	// ICMP family
	case proto == 1 || proto == 58:
		return "ICMP"
	default:
		return "Other"
	}
}

// AppCategory returns a traffic category for the given L7 application protocol.
func AppCategory(appProto string) string {
	switch appProto {
	case "HTTP", "HTTPS":
		return "Web"
	case "DNS", "NTP", "DHCP", "SNMP", "Syslog", "NetFlow":
		return "Network Services"
	case "SSH", "Telnet", "RDP", "SMB":
		return "Remote Access"
	case "SMTP", "IMAP", "POP3":
		return "Email"
	case "MySQL", "PostgreSQL", "Redis", "MongoDB":
		return "Database"
	case "FTP":
		return "File Transfer"
	case "LDAP":
		return "Directory"
	case "ICMP":
		return "Network Services"
	default:
		return "Other"
	}
}

// wellKnownAS maps common AS numbers to their organisation names.
var wellKnownAS = map[uint32]string{
	0:     "Private/Unknown",
	13335: "Cloudflare",
	15169: "Google",
	16509: "Amazon (AWS)",
	8075:  "Microsoft",
	32934: "Facebook (Meta)",
	20940: "Akamai",
	14618: "Amazon",
	16591: "Google Cloud",
	36459: "GitHub",
	54113: "Fastly",
	13414: "Twitter (X)",
	2906:  "Netflix",
	714:   "Apple",
	46489: "Twitch",
	36183: "Akamai",
	19551: "Incapsula",
	14061: "DigitalOcean",
	63949: "Linode (Akamai)",
	24940: "Hetzner",
	16276: "OVH",
	396982: "Google Cloud",
	8068:  "Microsoft (Azure)",
	8069:  "Microsoft (Azure)",
	3320:  "Deutsche Telekom",
	3356:  "Lumen/CenturyLink",
	6939:  "Hurricane Electric",
	174:   "Cogent",
	1299:  "Arelion (Telia)",
	2914:  "NTT",
	6461:  "Zayo",
	7018:  "AT&T",
	701:   "Verizon",
	7922:  "Comcast",
	22773: "Cox",
	20115: "Charter",
	6167:  "Verizon Business",
	209:   "CenturyLink",
	3257:  "GTT",
	4134:  "ChinaNet",
	4837:  "China Unicom",
	4808:  "China Unicom",
	9808:  "China Mobile",
	17676: "SoftBank",
	2516:  "KDDI",
	4766:  "Korea Telecom",
	9318:  "SK Broadband",
	4755:  "Tata Communications",
	9498:  "Bharti Airtel",
	18881: "Telefônica Brasil",
	28573: "Claro Brasil",
	12322: "Free (France)",
	5410:  "Bouygues Telecom",
	15557: "SFR (France)",
	6805:  "Telefónica Germany",
	12876: "Scaleway",
	197540: "Netcup",
	47541: "Vkontakte",
	13238: "Yandex",
}

// ASName returns a human-readable organisation name for common AS numbers.
// If the AS number is not in the well-known list, it returns "AS<number>".
func ASName(asn uint32) string {
	if name, ok := wellKnownAS[asn]; ok {
		return name
	}
	return fmt.Sprintf("AS%d", asn)
}
