package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type Proto int

const (
	ProtoTCP Proto = iota
	ProtoUDP
	ProtoICMP
)

type Line struct {
	Prefix   string
	Protocol Proto
	Source   string
	Dest     string
	// Non-empty only if Proto == "TCP"
	SourcePort string
	DestPort   string
}

type LineKey struct {
	Protocol Proto
	Source   string
	Dest     string
	// Non-empty only if Proto == "TCP"
	DestPort string
}

var (
	prefixR = regexp.MustCompile(`^\[(.+?)\]|fw`)
	keyvalR = regexp.MustCompile(`([[:alpha:]]+)=([[:alnum:].]+)`)
)

func stripTimestamp(line string) string {
	timestamp := prefixR.FindString(line)
	if timestamp == "" {
		// How tf would this happen
		return line
	}
	line, _ = strings.CutPrefix(line, timestamp)
	return line
}

func parseFields(line string) map[string]string {
	split := strings.Split(line, " ")

	fields := make(map[string]string)
	for _, field := range split {
		matches := keyvalR.FindStringSubmatch(field)
		if matches == nil {
			continue
		}
		fields[matches[1]] = matches[2]
	}
	return fields
}

// WARNING: It's possible for this function to return nil, nil. Please check both error and line!
func parseLine(line string, hasPrefix bool) (*Line, error) {
	if hasPrefix {
		line = stripTimestamp(line)
	}
	prefix := prefixR.FindString(line)
	if prefix == "" {
		// This just isn't a valid line, but no error happened
		return nil, nil
	}
	line, _ = strings.CutPrefix(line, prefix)
	fields := parseFields(line)

	proto, ok := fields["PROTO"]
	if !ok {
		return nil, fmt.Errorf("Line with prefix doesn't have a proto: %s", line)
	}

	src, ok := fields["SRC"]
	if !ok {
		return nil, fmt.Errorf("Line with prefix doesn't have a src: %s", line)
	}

	dst, ok := fields["DST"]
	if !ok {
		return nil, fmt.Errorf("Line with prefix doesn't have a src: %s", line)
	}

	if proto == "TCP" || proto == "UDP" {
		spt, ok := fields["SPT"]
		if !ok {
			return nil, fmt.Errorf("TCP/UDP log doesn't have a source port: %s", line)
		}

		dpt, ok := fields["DPT"]
		if !ok {
			return nil, fmt.Errorf("TCP/UDP log doesn't have a dest port: %s", line)
		}

		protoInt := ProtoTCP
		if proto == "UDP" {
			protoInt = ProtoUDP
		}

		return &Line{
			Prefix:     prefix,
			Protocol:   protoInt,
			Source:     src,
			Dest:       dst,
			SourcePort: spt,
			DestPort:   dpt,
		}, nil
	} else if proto == "ICMP" {
		return &Line{
			Prefix:     prefix,
			Protocol:   ProtoICMP,
			Source:     src,
			Dest:       dst,
			SourcePort: "",
			DestPort:   "",
		}, nil
	} else {
		return nil, fmt.Errorf("Line with prefix has proto, but not recognized: %s", line)
	}
}

// Parses firewall logs.
func main() {
	dmesg := exec.Command("dmesg", "-t")
	out, err := dmesg.Output()
	hasPrefix := false
	if err != nil {
		dmesg = exec.Command("dmesg")
		out, err = dmesg.Output()
		if err != nil {
			os.Exit(1)
		}
		hasPrefix = true
	}

	lines := strings.Split(string(out), "\n")

	prefixes := make(map[string]map[LineKey]int)

	for _, line := range lines {
		line, err := parseLine(line, hasPrefix)
		if err != nil {
			fmt.Println(err.Error())
		}
		if line == nil {
			continue
		}
		key := LineKey{
			Protocol: line.Protocol,
			Source:   line.Source,
			Dest:     line.Dest,
			DestPort: line.DestPort,
		}
		counts := prefixes[line.Prefix]
		if counts == nil {
			counts = make(map[LineKey]int)
			prefixes[line.Prefix] = counts
		}
		counts[key]++
	}

	for prefix, counts := range prefixes {
		for line, count := range counts {
			src := line.Source
			dst := line.Dest
			if line.Protocol == ProtoTCP || line.Protocol == ProtoUDP {
				// src = fmt.Sprintf("%s:%s", line.Source, *line.SourcePort)
				dst = fmt.Sprintf("%s:%s", line.Dest, line.DestPort)
			}
			key := fmt.Sprintf("%s -> %s:", src, dst)
			fmt.Printf("%-10s: %-35s  %8d\n", prefix, key, count)
		}
	}
}
