package capture

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file implements a pure-Go userspace BPF filter (no libpcap/cgo) so
// that configured filter expressions are actually applied to captured frames.
// It supports the common tcpdump subset:
//
//	protocol keywords: ip, ip6, arp, tcp, udp, icmp, icmp6
//	primitives:        host X, net X[/bits], port N, greater N, less N
//	direction:         src, dst
//	proto qualifiers:  e.g. "tcp port 80", "udp host 10.0.0.1"
//	combinators:       and, or, not, parentheses
//
// Grammar (recursive descent):
//
//	orExpr  := andExpr ("or" andExpr)*
//	andExpr := unary ("and" unary)*
//	unary   := "not" unary | "(" orExpr ")" | primitive

// bpfDirSrc and bpfDirDst are direction qualifier bits.
const (
	bpfDirSrc = 1
	bpfDirDst = 2
)

// bpfPred is a compiled predicate evaluated against a parsed frame.
type bpfPred func(fi *bpfFrameInfo) bool

// bpfFrameInfo holds the fields of a raw Ethernet frame needed for filtering.
type bpfFrameInfo struct {
	length    int
	etherType uint16
	srcIP     net.IP
	dstIP     net.IP
	proto     uint8 // L4 protocol number (valid when hasL4)
	hasL4     bool
	srcPort   uint16
	dstPort   uint16
	hasPorts  bool
}

// compileBPF compiles a tcpdump-style filter expression into a predicate over
// raw Ethernet frames. It returns a descriptive error for unsupported syntax.
func compileBPF(expr string) (func(frame []byte) bool, error) {
	tokens := tokenizeBPF(expr)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("bpf: empty filter expression")
	}

	p := &bpfParser{tokens: tokens}
	pred, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, fmt.Errorf("bpf: unexpected token %q", p.tokens[p.pos])
	}

	return func(frame []byte) bool {
		return pred(parseFrameBPF(frame))
	}, nil
}

// tokenizeBPF splits an expression on whitespace and parentheses.
func tokenizeBPF(expr string) []string {
	var tokens []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	for _, r := range expr {
		switch r {
		case ' ', '\t', '\n', '\r':
			flush()
		case '(', ')':
			flush()
			tokens = append(tokens, string(r))
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return tokens
}

// bpfParser is a recursive-descent parser over a token stream.
type bpfParser struct {
	tokens []string
	pos    int
}

// peek returns the current token lowercased (keywords are case-insensitive),
// or "" at end of input.
func (p *bpfParser) peek() string {
	if p.pos < len(p.tokens) {
		return strings.ToLower(p.tokens[p.pos])
	}
	return ""
}

// next consumes and returns the current token (lowercased), or "" at end.
func (p *bpfParser) next() string {
	tok := p.peek()
	if tok != "" {
		p.pos++
	}
	return tok
}

// nextValue consumes the next raw token as a value for a primitive.
func (p *bpfParser) nextValue(what string) (string, error) {
	if p.pos >= len(p.tokens) {
		return "", fmt.Errorf("bpf: missing value for %q", what)
	}
	val := p.tokens[p.pos]
	p.pos++
	return val, nil
}

func (p *bpfParser) parseOr() (bpfPred, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "or" {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l := left
		left = func(fi *bpfFrameInfo) bool { return l(fi) || right(fi) }
	}
	return left, nil
}

func (p *bpfParser) parseAnd() (bpfPred, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "and" {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l := left
		left = func(fi *bpfFrameInfo) bool { return l(fi) && right(fi) }
	}
	return left, nil
}

func (p *bpfParser) parseUnary() (bpfPred, error) {
	switch p.peek() {
	case "not":
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return func(fi *bpfFrameInfo) bool { return !inner(fi) }, nil
	case "(":
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("bpf: missing closing parenthesis")
		}
		p.next()
		return inner, nil
	default:
		return p.parsePrimitive()
	}
}

// parsePrimitive parses direction/protocol qualifiers followed by a core
// primitive (host/net/port/greater/less), or a standalone protocol keyword.
func (p *bpfParser) parsePrimitive() (bpfPred, error) {
	dir := 0
	protoQual := -1 // L4 protocol qualifier (-1 = none)
	etherQual := -1 // ethertype qualifier (-1 = none)

qualifiers:
	for {
		switch tok := p.peek(); tok {
		case "src":
			p.next()
			dir |= bpfDirSrc
		case "dst":
			p.next()
			dir |= bpfDirDst
		case "tcp", "udp", "icmp", "icmp6":
			if protoQual >= 0 || etherQual >= 0 {
				return nil, fmt.Errorf("bpf: multiple protocol qualifiers near %q", tok)
			}
			p.next()
			protoQual = bpfProtoNumber(tok)
		case "ip", "ip6", "arp":
			if protoQual >= 0 || etherQual >= 0 {
				return nil, fmt.Errorf("bpf: multiple protocol qualifiers near %q", tok)
			}
			p.next()
			etherQual = int(bpfEtherType(tok))
		default:
			break qualifiers
		}
	}

	var preds []bpfPred
	if protoQual >= 0 {
		preds = append(preds, bpfProtoPred(uint8(protoQual)))
	}
	if etherQual >= 0 {
		preds = append(preds, bpfEtherPred(uint16(etherQual)))
	}

	tok := p.peek()
	switch tok {
	case "host", "net", "port", "greater", "less":
		p.next()
		core, err := p.parseCore(tok, dir, etherQual)
		if err != nil {
			return nil, err
		}
		preds = append(preds, core)
		return bpfAnd(preds...), nil
	case "":
		if len(preds) == 0 {
			return nil, fmt.Errorf("bpf: unexpected end of expression")
		}
		// Standalone protocol keyword, e.g. "not icmp".
		return bpfAnd(preds...), nil
	default:
		if len(preds) > 0 {
			// Standalone protocol keyword followed by a combinator, e.g. "tcp and ...".
			return bpfAnd(preds...), nil
		}
		return nil, fmt.Errorf("bpf: unsupported token %q", p.tokens[p.pos])
	}
}

// parseCore parses the value and builds the predicate for host/net/port/
// greater/less primitives.
func (p *bpfParser) parseCore(kind string, dir, etherQual int) (bpfPred, error) {
	val, err := p.nextValue(kind)
	if err != nil {
		return nil, err
	}

	switch kind {
	case "host":
		if etherQual == 0x0806 {
			return nil, fmt.Errorf("bpf: %q cannot be combined with arp", kind)
		}
		ip := net.ParseIP(val)
		if ip == nil {
			return nil, fmt.Errorf("bpf: invalid host address %q", val)
		}
		return bpfHostPred(dir, ip), nil
	case "net":
		if etherQual == 0x0806 {
			return nil, fmt.Errorf("bpf: %q cannot be combined with arp", kind)
		}
		ip, bits, err := parseNetBPF(val)
		if err != nil {
			return nil, err
		}
		return bpfNetPred(dir, ip, bits), nil
	case "port":
		n, err := strconv.ParseUint(val, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bpf: invalid port %q", val)
		}
		return bpfPortPred(dir, uint16(n)), nil
	case "greater", "less":
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bpf: invalid length %q", val)
		}
		return bpfLenPred(kind == "greater", uint32(n)), nil
	}
	return nil, fmt.Errorf("bpf: unsupported primitive %q", kind)
}

// bpfProtoNumber maps a protocol keyword to its IP protocol number.
func bpfProtoNumber(name string) int {
	switch name {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmp6":
		return 58
	}
	return -1
}

// bpfEtherType maps a link-layer protocol keyword to its EtherType.
func bpfEtherType(name string) uint16 {
	switch name {
	case "ip":
		return 0x0800
	case "ip6":
		return 0x86DD
	case "arp":
		return 0x0806
	}
	return 0
}

// parseNetBPF parses "X" or "X/bits" into a network address and prefix length.
func parseNetBPF(val string) (net.IP, int, error) {
	ipStr, bitsStr, hasBits := strings.Cut(val, "/")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("bpf: invalid network address %q", val)
	}

	maxBits := 128
	if ip.To4() != nil {
		maxBits = 32
	}
	bits := maxBits
	if hasBits {
		n, err := strconv.Atoi(bitsStr)
		if err != nil || n < 0 {
			return nil, 0, fmt.Errorf("bpf: invalid prefix length %q", bitsStr)
		}
		bits = n
	}
	if bits > maxBits {
		return nil, 0, fmt.Errorf("bpf: prefix length %d too large for %q", bits, ipStr)
	}
	return ip, bits, nil
}

// bpfAnd combines predicates with logical AND.
func bpfAnd(preds ...bpfPred) bpfPred {
	return func(fi *bpfFrameInfo) bool {
		for _, pr := range preds {
			if !pr(fi) {
				return false
			}
		}
		return true
	}
}

// bpfProtoPred matches the L4 protocol number (TCP/UDP/ICMP/ICMP6).
func bpfProtoPred(proto uint8) bpfPred {
	return func(fi *bpfFrameInfo) bool {
		return fi.hasL4 && fi.proto == proto
	}
}

// bpfEtherPred matches the (innermost) EtherType (ip/ip6/arp).
func bpfEtherPred(etherType uint16) bpfPred {
	return func(fi *bpfFrameInfo) bool {
		return fi.etherType == etherType
	}
}

// bpfHostPred matches src and/or dst IP equal to ip.
func bpfHostPred(dir int, ip net.IP) bpfPred {
	match := func(fi *bpfFrameInfo, candidate net.IP) bool {
		return candidate != nil && candidate.Equal(ip)
	}
	return func(fi *bpfFrameInfo) bool {
		if dir == 0 {
			return match(fi, fi.srcIP) || match(fi, fi.dstIP)
		}
		if dir&bpfDirSrc != 0 && match(fi, fi.srcIP) {
			return true
		}
		if dir&bpfDirDst != 0 && match(fi, fi.dstIP) {
			return true
		}
		return false
	}
}

// bpfNetPred matches src and/or dst IP within network/bits.
func bpfNetPred(dir int, network net.IP, bits int) bpfPred {
	match := func(candidate net.IP) bool {
		if candidate == nil {
			return false
		}
		a, b := candidate.To4(), network.To4()
		if a != nil && b != nil {
			if bits > 32 {
				return false
			}
			return bpfMaskedEqual(a, b, bits)
		}
		a16, b16 := candidate.To16(), network.To16()
		if a16 == nil || b16 == nil {
			return false
		}
		if bits > 128 {
			return false
		}
		return bpfMaskedEqual(a16, b16, bits)
	}
	return func(fi *bpfFrameInfo) bool {
		if dir == 0 {
			return match(fi.srcIP) || match(fi.dstIP)
		}
		if dir&bpfDirSrc != 0 && match(fi.srcIP) {
			return true
		}
		if dir&bpfDirDst != 0 && match(fi.dstIP) {
			return true
		}
		return false
	}
}

// bpfMaskedEqual reports whether the first bits of a and b are equal.
func bpfMaskedEqual(a, b []byte, bits int) bool {
	if len(a) != len(b) || bits > len(a)*8 {
		return false
	}
	full := bits / 8
	for i := 0; i < full; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	rem := bits % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF) << (8 - rem)
	return a[full]&mask == b[full]&mask
}

// bpfPortPred matches src and/or dst L4 port.
func bpfPortPred(dir int, port uint16) bpfPred {
	return func(fi *bpfFrameInfo) bool {
		if !fi.hasPorts {
			return false
		}
		if dir == 0 {
			return fi.srcPort == port || fi.dstPort == port
		}
		if dir&bpfDirSrc != 0 && fi.srcPort == port {
			return true
		}
		if dir&bpfDirDst != 0 && fi.dstPort == port {
			return true
		}
		return false
	}
}

// bpfLenPred matches the frame length (greater N / less N).
func bpfLenPred(greater bool, n uint32) bpfPred {
	return func(fi *bpfFrameInfo) bool {
		if greater {
			return fi.length > int(n)
		}
		return fi.length < int(n)
	}
}

// parseFrameBPF extracts the filterable fields from a raw Ethernet frame,
// walking stacked 802.1Q/802.1ad tags and IPv6 extension headers.
func parseFrameBPF(frame []byte) *bpfFrameInfo {
	fi := &bpfFrameInfo{length: len(frame)}
	if len(frame) < 14 {
		return fi
	}

	fi.etherType = uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	for fi.etherType == 0x8100 || fi.etherType == 0x88a8 {
		if len(frame) < offset+4 {
			return fi // truncated VLAN tag
		}
		fi.etherType = uint16(frame[offset+2])<<8 | uint16(frame[offset+3])
		offset += 4
	}

	switch fi.etherType {
	case 0x0800: // IPv4
		if len(frame) < offset+20 {
			return fi
		}
		ihl := int(frame[offset]&0x0f) * 4
		if ihl < 20 || len(frame) < offset+ihl {
			return fi
		}
		fi.proto = frame[offset+9]
		fi.hasL4 = true
		fi.srcIP = net.IP(frame[offset+12 : offset+16])
		fi.dstIP = net.IP(frame[offset+16 : offset+20])
		l4 := frame[offset+ihl:]
		if (fi.proto == 6 || fi.proto == 17) && len(l4) >= 4 {
			fi.srcPort = uint16(l4[0])<<8 | uint16(l4[1])
			fi.dstPort = uint16(l4[2])<<8 | uint16(l4[3])
			fi.hasPorts = true
		}
	case 0x86DD: // IPv6
		if len(frame) < offset+40 {
			return fi
		}
		nh, l4off, ok := ipv6L4Offset(frame[offset:])
		if !ok {
			nh = frame[offset+6]
		}
		fi.proto = nh
		fi.hasL4 = ok
		fi.srcIP = net.IP(frame[offset+8 : offset+24])
		fi.dstIP = net.IP(frame[offset+24 : offset+40])
		if ok {
			l4 := frame[offset+l4off:]
			if (nh == 6 || nh == 17) && len(l4) >= 4 {
				fi.srcPort = uint16(l4[0])<<8 | uint16(l4[1])
				fi.dstPort = uint16(l4[2])<<8 | uint16(l4[3])
				fi.hasPorts = true
			}
		}
	}
	return fi
}
