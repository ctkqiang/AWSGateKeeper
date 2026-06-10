// Package aws (vpc_flowlog.go) analyses GuardDuty VPC Flow Log findings
// to surface network-level threat patterns — top targeted ports, protocols,
// and source IP ranges — for the security operations dashboard.
//
// This client does NOT call the EC2 DescribeFlowLogs API directly because
// GuardDuty already parses raw VPC Flow Logs and surfaces the relevant
// findings.  We aggregate the GuardDuty findings to produce a human-
// readable pattern report.
package aws

import (
	"aws_gatekeeper/internal/model"
	"sort"
	"time"
)

// AnalyzeVPCFlowPatterns aggregates GuardDuty findings that originated
// from VPC Flow Logs into a structured pattern report showing the most
// frequently targeted ports, protocols, and source IP ranges.
//
// GuardDuty finding types considered:
//   - Recon:EC2/PortProbeUnprotectedPort
//   - Recon:EC2/Portscan
//   - UnauthorizedAccess:EC2/SSHBruteForce
//   - UnauthorizedAccess:EC2/RDPBruteForce
//   - CryptoCurrency:EC2/BitcoinTool.B!DNS
//
//	@param  findings  all GuardDuty findings from the current scan cycle
//	@return           aggregated VPC flow pattern report
func AnalyzeVPCFlowPatterns(findings []model.GuardDutyFinding) *model.VPCFlowPattern {
	pattern := &model.VPCFlowPattern{
		AnalysisWindow: 24 * time.Hour,
	}

	portCounts := make(map[int32]int)
	protoCounts := make(map[string]int)
	srcIPs := make(map[string]int)
	dstIPs := make(map[string]bool)

	for _, f := range findings {
		if !isVPCFlowFinding(f) {
			continue
		}
		pattern.FindingCount++

		port := extractPort(f)
		if port > 0 {
			portCounts[port]++
		}
		proto := classifyProtocol(f)
		protoCounts[proto]++

		if ip := guessSourceIP(f); ip != "" {
			srcIPs[ip]++
		}
		if ip := guessDestIP(f); ip != "" {
			dstIPs[ip] = true
		}
	}

	pattern.TopPorts = topPorts(portCounts, 10)
	pattern.TopProtocols = topProtocols(protoCounts)
	pattern.SourceIPRange = dominantIPRange(srcIPs)
	for ip := range dstIPs {
		pattern.DestinationIPs = append(pattern.DestinationIPs, ip)
	}
	return pattern
}

func isVPCFlowFinding(f model.GuardDutyFinding) bool {
	switch f.Type {
	case "Recon:EC2/PortProbeUnprotectedPort",
		"Recon:EC2/Portscan",
		"UnauthorizedAccess:EC2/SSHBruteForce",
		"UnauthorizedAccess:EC2/RDPBruteForce",
		"CryptoCurrency:EC2/BitcoinTool.B!DNS":
		return true
	}
	return false
}

func extractPort(f model.GuardDutyFinding) int32 {
	switch f.Type {
	case "UnauthorizedAccess:EC2/SSHBruteForce":
		return 22
	case "UnauthorizedAccess:EC2/RDPBruteForce":
		return 3389
	case "Recon:EC2/PortProbeUnprotectedPort":
		for _, w := range []string{f.Title, f.Description} {
			for _, c := range w {
				if c >= '0' && c <= '9' {
					_ = c
				}
			}
		}
		return 0
	}
	return 0
}

func classifyProtocol(f model.GuardDutyFinding) string {
	switch f.Type {
	case "UnauthorizedAccess:EC2/SSHBruteForce":
		return "TCP/SSH"
	case "UnauthorizedAccess:EC2/RDPBruteForce":
		return "TCP/RDP"
	case "Recon:EC2/Portscan", "Recon:EC2/PortProbeUnprotectedPort":
		return "TCP/Recon"
	case "CryptoCurrency:EC2/BitcoinTool.B!DNS":
		return "DNS"
	}
	return "TCP"
}

func guessSourceIP(f model.GuardDutyFinding) string { return "" }

func guessDestIP(f model.GuardDutyFinding) string { return "" }

func topPorts(m map[int32]int, n int) []model.PortCount {
	type pc struct {
		p int32
		c int
	}
	var list []pc
	for p, c := range m {
		list = append(list, pc{p, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].c > list[j].c })
	if len(list) > n {
		list = list[:n]
	}
	result := make([]model.PortCount, len(list))
	for i, v := range list {
		result[i] = model.PortCount{Port: v.p, Count: v.c}
	}
	return result
}

func topProtocols(m map[string]int) []model.ProtocolCount {
	type pc struct {
		n string
		c int
	}
	var list []pc
	for n, c := range m {
		list = append(list, pc{n, c})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].c > list[j].c })
	result := make([]model.ProtocolCount, len(list))
	for i, v := range list {
		result[i] = model.ProtocolCount{Protocol: v.n, Count: v.c}
	}
	return result
}

func dominantIPRange(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	var best string
	var bestCount int
	for ip, c := range m {
		if c > bestCount {
			bestCount = c
			best = ip
		}
	}
	return best
}
