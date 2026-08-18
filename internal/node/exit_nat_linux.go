//go:build linux

package node

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

const exitNFTTable = "hopscotch_exit"

// writeExitEgress injects a packet into the TUN so the kernel can forward/SNAT it.
func (n *Node) writeExitEgress(inner []byte) error {
	n.mu.Lock()
	d := n.tun
	n.mu.Unlock()
	if d == nil {
		return fmt.Errorf("no tun")
	}
	return d.WritePacket(inner)
}

// setupExitNAT enables IPv4/IPv6 forwarding, accepts FORWARD for the TUN, and
// MASQUERADEs egress. Without a forward accept, VPS images with a DROP policy
// blackhole exit traffic (clients see hung TCP).
func (n *Node) setupExitNAT(ifName string) (func() error, error) {
	if !safeExitIfName(ifName) {
		return nil, fmt.Errorf("exit nat: bad ifname %q", ifName)
	}
	for _, kv := range []struct {
		key string
		val string
	}{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.forwarding", "1"},
		{"net.ipv6.conf.all.forwarding", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf." + ifName + ".rp_filter", "0"},
	} {
		if err := sysctlSet(kv.key, kv.val); err != nil {
			if strings.Contains(kv.key, "rp_filter") {
				continue
			}
			return nil, fmt.Errorf("exit nat %s=%s: %w", kv.key, kv.val, err)
		}
	}
	if err := deleteExitNFTTable(); err != nil {
		return nil, fmt.Errorf("exit nat nft reset: %w", err)
	}
	if err := installExitNFT(ifName); err != nil {
		return nil, err
	}
	fwdRules, err := insertFilterForward(ifName)
	if err != nil {
		_ = deleteExitNFTTable()
		return nil, err
	}

	n.log.Printf("exit      nat inet hopscotch_exit masquerade + forward (oif != %s)", ifName)
	return func() error {
		if err := deleteFilterForward(fwdRules); err != nil {
			return err
		}
		return deleteExitNFTTable()
	}, nil
}

func sysctlSet(key, val string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(val+"\n"), 0)
}

func installExitNFT(ifName string) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("exit nat nft conn: %w", err)
	}
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   exitNFTTable,
	})
	natChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	fwdChain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityRef(-150),
	})
	ifNameData := append([]byte(ifName), 0)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: natChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     ifNameData,
			},
			&expr.Masq{},
		},
	})
	for _, key := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: fwdChain,
			Exprs: []expr.Any{
				&expr.Meta{Key: key, Register: 1},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     ifNameData,
				},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("exit nat nft: %w", err)
	}
	return nil
}

func deleteExitNFTTable() error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if t.Family == nftables.TableFamilyINet && t.Name == exitNFTTable {
			conn.DelTable(t)
		}
	}
	return conn.Flush()
}

func insertFilterForward(ifName string) ([]*nftables.Rule, error) {
	ifNameData := append([]byte(ifName), 0)
	var rules []*nftables.Rule
	for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		conn, err := nftables.New()
		if err != nil {
			deleteFilterForward(rules)
			return nil, err
		}
		table := &nftables.Table{Family: family, Name: "filter"}
		chain := &nftables.Chain{Name: "FORWARD", Table: table}
		for _, key := range []expr.MetaKey{expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME} {
			rule := conn.InsertRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: key, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ifNameData,
					},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
			})
			rules = append(rules, rule)
		}
		if err := conn.Flush(); err != nil {
			deleteFilterForward(rules)
			return nil, err
		}
	}
	return rules, nil
}

func deleteFilterForward(rules []*nftables.Rule) error {
	if len(rules) == 0 {
		return nil
	}
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	for i := len(rules) - 1; i >= 0; i-- {
		conn.DelRule(rules[i])
	}
	return conn.Flush()
}

func safeExitIfName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
