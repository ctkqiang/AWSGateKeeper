// Package aws (route53_dns.go) integrates Route53 Resolver DNS Firewall
// with the GuardDuty threat pipeline.  When GuardDuty detects a DNS-based
// threat (CryptoCurrency, DNS data exfiltration, or domain generation
// algorithm), this client surfaces the malicious domains for automated
// blocking via DNS Firewall domain lists.
//
// Required IAM permissions for the calling principal:
//
//	route53resolver:ListFirewallDomainLists
//	route53resolver:UpdateFirewallDomains
package aws

import (
	"aws_gatekeeper/internal/model"
	"context"
	"fmt"
	"strings"

	aws_sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
)

// DNSFirewallClient wraps the Route53 Resolver DNS Firewall SDK for
// automated threat-domain blocking.
type DNSFirewallClient struct {
	client *route53resolver.Client
}

// NewDNSFirewallClient creates a DNSFirewallClient from the shared SDK config.
func NewDNSFirewallClient(cfg aws_sdk.Config) *DNSFirewallClient {
	return &DNSFirewallClient{client: route53resolver.NewFromConfig(cfg)}
}

// ExtractDNSThreats scans GuardDuty findings for DNS-related anomalies
// and returns a list of domains that should be blocked.
func ExtractDNSThreats(findings []model.GuardDutyFinding) []model.DNSThreatEntry {
	var threats []model.DNSThreatEntry
	seen := make(map[string]bool)
	for _, f := range findings {
		if !isDNSRelatedFinding(f) {
			continue
		}
		domain := extractDomainFromFinding(f)
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		action := "BLOCK"
		if f.Severity < model.SeverityMedium {
			action = "ALERT"
		}
		threats = append(threats, model.DNSThreatEntry{
			Domain:      domain,
			FindingID:   f.ID,
			Severity:    severityStr(f.Severity),
			RuleAction:  action,
			Description: fmt.Sprintf("GuardDuty %s: %s", f.Type, truncDesc(f.Title, 80)),
		})
	}
	return threats
}

// BlockDomain adds a domain to the specified DNS Firewall domain list.
func (c *DNSFirewallClient) BlockDomain(ctx context.Context, domainListID, domain, action string) error {
	_, err := c.client.UpdateFirewallDomains(ctx, &route53resolver.UpdateFirewallDomainsInput{
		FirewallDomainListId: aws_sdk.String(domainListID),
		Operation:            r53types.FirewallDomainUpdateOperationAdd,
		Domains:              []string{domain},
	})
	if err != nil {
		return fmt.Errorf("add %s to domain list %s: %w", domain, domainListID, err)
	}
	return nil
}

func isDNSRelatedFinding(f model.GuardDutyFinding) bool {
	t := strings.ToLower(f.Type + " " + f.Title)
	return strings.Contains(t, "dns") ||
		strings.Contains(t, "cryptocurrency") ||
		strings.Contains(t, "bitcoin") ||
		strings.Contains(t, "dataexfiltration") ||
		strings.Contains(t, "domain generation")
}

func extractDomainFromFinding(f model.GuardDutyFinding) string {
	for _, word := range strings.Fields(f.Title + " " + f.Description) {
		word = strings.Trim(word, ".,;:\"()[]{}")
		if strings.Contains(word, ".") && !strings.Contains(word, "arn:") && len(word) > 4 {
			return strings.ToLower(word)
		}
	}
	return ""
}

func severityStr(s model.FindingSeverity) string {
	switch s {
	case model.SeverityHigh:
		return "HIGH"
	case model.SeverityMedium:
		return "MEDIUM"
	case model.SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func truncDesc(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
