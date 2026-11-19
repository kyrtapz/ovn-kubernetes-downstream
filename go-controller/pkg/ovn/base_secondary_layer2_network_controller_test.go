// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovn

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"

	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	ovntest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
)

func Test_getDenyARPAndNSOnMACVRF(t *testing.T) {
	controllerName := "testController"
	macvrfportName := "testmacvrfportName"
	mac := "00:11:22:33:44:55"
	gwIPv4 := "100.200.0.1"
	gwIPv6 := "fd11::1"
	expectACLS := []*nbdb.ACL{
		libovsdbutil.BuildACLWithDefaultTier(
			libovsdbops.NewDbObjectIDs(
				libovsdbops.ACLUDN,
				controllerName,
				map[libovsdbops.ExternalIDKey]string{
					libovsdbops.ObjectNameKey:      "DenyOnMACVRF-GatewayARP",
					libovsdbops.PolicyDirectionKey: string(libovsdbutil.ACLIngress),
				},
			),
			types.DefaultDenyPriority,
			fmt.Sprintf(
				"outport==%q && eth.dst==%s && arp && arp.op==1 && arp.tpa==%s",
				macvrfportName,
				mac,
				gwIPv4,
			),
			nbdb.ACLActionDrop,
			nil,
			libovsdbutil.LportIngress,
		),
		libovsdbutil.BuildACLWithDefaultTier(
			libovsdbops.NewDbObjectIDs(
				libovsdbops.ACLUDN,
				controllerName,
				map[libovsdbops.ExternalIDKey]string{
					libovsdbops.ObjectNameKey:      "DenyOnMACVRF-GatewayNS",
					libovsdbops.PolicyDirectionKey: string(libovsdbutil.ACLIngress),
				},
			),
			types.DefaultDenyPriority,
			fmt.Sprintf(
				"outport==%q && eth.dst==%s && nd && icmp.type==135 && nd.target==%s",
				macvrfportName,
				mac,
				gwIPv6,
			),
			nbdb.ACLActionDrop,
			nil,
			libovsdbutil.LportIngress,
		),
	}
	tests := []struct {
		name       string
		gwIfAddrv4 *net.IPNet
		gwIfAddrv6 *net.IPNet
		want       []*nbdb.ACL
	}{
		{
			name:       "deny for IPv4",
			gwIfAddrv4: &net.IPNet{IP: ovntest.MustParseIP(gwIPv4)},
			want:       []*nbdb.ACL{expectACLS[0]},
		},
		{
			name:       "deny for IPv6",
			gwIfAddrv6: &net.IPNet{IP: ovntest.MustParseIP(gwIPv6)},
			want:       []*nbdb.ACL{expectACLS[1]},
		},
		{
			name:       "deny for dual-stack",
			gwIfAddrv4: &net.IPNet{IP: ovntest.MustParseIP(gwIPv4)},
			gwIfAddrv6: &net.IPNet{IP: ovntest.MustParseIP(gwIPv6)},
			want:       expectACLS,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getDenyARPAndNSOnMACVRF(
				controllerName,
				macvrfportName,
				ovntest.MustParseMAC(mac),
				tt.gwIfAddrv4,
				tt.gwIfAddrv6,
			)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("getDenyARPAndNSOnMACVRF() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMACVRFTransitACLs(t *testing.T) {
	const (
		v4Match = "(ip4.dst == $v4pods && ((tcp && ip4.src == $v4pods) || (icmp4 && icmp4.type == {3, 11, 12})))"
		v6Match = "(ip6.dst == $v6pods && ((tcp && ip6.src == $v6pods) || (icmp6 && icmp6.type == {1, 2, 3, 4})))"
	)
	for _, tc := range []struct{ name, v4, v6, endpoints string }{
		{"IPv4", "v4pods", "", v4Match},
		{"IPv6", "", "v6pods", v6Match},
		{"dual stack", "v4pods", "v6pods", v4Match + " || " + v6Match},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acls := macVRFTransitACLs("controller", "handoff", tc.v4, tc.v6)
			matches := map[string]string{
				nbdb.ACLDirectionFromLport: "inport", nbdb.ACLDirectionToLport: "outport",
			}
			for _, acl := range acls {
				field, ok := matches[acl.Direction]
				want := fmt.Sprintf(`%s == "handoff" && !eth.mcast && (%s)`, field, tc.endpoints)
				if !ok || acl.Match != want || acl.Action != nbdb.ACLActionAllowStateless || len(acl.Options) != 0 {
					t.Errorf("unexpected %s ACL: match %q, action %q, options %v", acl.Direction, acl.Match, acl.Action, acl.Options)
				}
				delete(matches, acl.Direction)
			}
			if len(matches) != 0 {
				t.Errorf("missing transit ACLs for %v", matches)
			}
		})
	}
}
