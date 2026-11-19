// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovn

import (
	"fmt"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/utils/net"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	libovsdbutil "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/util"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/node/controllers/evpn"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

const (
	dynamicRoutingRedistribute = "dynamic-routing-redistribute"
	dynamicRoutingNoLearning   = "dynamic-routing-no-learning"
	dynamicRoutingAdvertise    = "dynamic-routing-advertise"

	// OVN requires an address on the EVPN router port. The isolated stitch
	// switch resolves remote router MACs from EVPN, so a link-local IP suffices.
	evpnStitchIPv4 = "169.254.255.1/32"

	macVRFTransitACLPriority = 1
)

func nativeEVPNSwitchConfig(vtep string, vni int32, svi, advertisePort string) map[string]string {
	return map[string]string{
		"dynamic-routing-vni":              strconv.Itoa(int(vni)),
		"dynamic-routing-bridge-ifname":    svi,
		"dynamic-routing-advertise-ifname": advertisePort,
		"dynamic-routing-vxlan-ifname": strings.Join([]string{
			evpn.GetEVPNVXLANName(vtep, utilnet.IPv4),
			evpn.GetEVPNVXLANName(vtep, utilnet.IPv6),
		}, ","),
	}
}

func (oc *BaseLayer2UserDefinedNetworkController) syncMACVRFSwitch(sw *nbdb.LogicalSwitch) error {
	options := nativeEVPNSwitchConfig(oc.EVPNVTEPName(), oc.EVPNMACVRFVNI(),
		evpn.GetEVPNL2SVIName(oc), evpn.GetEVPNOVSPortName(oc))
	options[dynamicRoutingRedistribute] = "fdb,ip"
	native := util.UsesOVNNativeEVPN(oc)
	if !native {
		for key := range options {
			options[key] = ""
		}
	}
	if err := libovsdbops.UpdateLogicalSwitchSetOtherConfig(oc.nbClient, &nbdb.LogicalSwitch{
		Name: sw.Name, OtherConfig: options,
	}); err != nil {
		return err
	}
	portName := util.GetMACVRFPortName(sw.Name)
	if native {
		// Remove both transit ACLs and their host-facing port together on migration.
		acls, err := libovsdbops.FindACLsWithPredicate(oc.nbClient, libovsdbops.GetPredicate[*nbdb.ACL](macVRFTransitACLIDs(oc.controllerName), nil))
		if err != nil {
			return err
		}
		ops, err := libovsdbops.RemoveACLsFromLogicalSwitchOps(oc.nbClient, nil, sw.Name, acls...)
		if err != nil {
			return err
		}
		ops, err = libovsdbops.DeleteLogicalSwitchPortsOps(oc.nbClient, ops, sw, &nbdb.LogicalSwitchPort{Name: portName})
		if err != nil {
			return err
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		return err
	}
	if config.Gateway.Mode == config.GatewayModeLocal && oc.IsPrimaryNetwork() {
		// The empty selectors include workload IPs in every namespace on this
		// network. Legacy network policy selection excludes host-network pods.
		_, v4, v6, err := oc.addressSetManager.EnsureAddressSet(&metav1.LabelSelector{}, &metav1.LabelSelector{}, nil, "",
			"MACVRFTransit/"+portName, oc.controllerName, oc.GetNetInfo(), true)
		if err != nil {
			return fmt.Errorf("ensuring pod address set for %s: %w", portName, err)
		}
		acls := macVRFTransitACLs(oc.controllerName, portName, v4, v6)
		ops, err := libovsdbops.CreateOrUpdateACLsOps(oc.nbClient, nil, oc.GetSamplingConfig(), acls...)
		if err != nil {
			return err
		}
		ops, err = libovsdbops.AddACLsToLogicalSwitchOps(oc.nbClient, ops, sw.Name, acls...)
		if err != nil {
			return err
		}
		_, err = libovsdbops.TransactAndCheck(oc.nbClient, ops)
		return err
	}
	return nil
}

func macVRFTransitACLIDs(controllerName string) *libovsdbops.DbObjectIDs {
	return libovsdbops.NewDbObjectIDs(libovsdbops.ACLUDN, controllerName, map[libovsdbops.ExternalIDKey]string{
		libovsdbops.ObjectNameKey: "MACVRFTransit",
	})
}

// Both directions must select the same connections. Skipping only the output
// lookup leaves the return SYN-ACK without state in the MAC-VRF port's zone.
// A router can originate ICMP errors for these connections. Pass their errors
// to the destination pod's CT zone, where the original connection and any
// load-balancer translation exist.
func macVRFTransitACLs(controllerName, portName, v4, v6 string) []*nbdb.ACL {
	var endpoints []string
	if v4 != "" {
		endpoints = append(endpoints, fmt.Sprintf("(ip4.dst == $%[1]s && ((tcp && ip4.src == $%[1]s) || (icmp4 && icmp4.type == {3, 11, 12})))", v4))
	}
	if v6 != "" {
		endpoints = append(endpoints, fmt.Sprintf("(ip6.dst == $%[1]s && ((tcp && ip6.src == $%[1]s) || (icmp6 && icmp6.type == {1, 2, 3, 4})))", v6))
	}
	match := fmt.Sprintf("%q && !eth.mcast && (%s)", portName, strings.Join(endpoints, " || "))
	ids := macVRFTransitACLIDs(controllerName)
	return []*nbdb.ACL{
		libovsdbutil.BuildACLWithDefaultTier(ids.AddIDs(map[libovsdbops.ExternalIDKey]string{
			libovsdbops.PolicyDirectionKey: string(libovsdbutil.ACLIngress),
		}), macVRFTransitACLPriority, "outport == "+match, nbdb.ACLActionAllowStateless, nil, libovsdbutil.LportIngress),
		libovsdbutil.BuildACLWithDefaultTier(ids.AddIDs(map[libovsdbops.ExternalIDKey]string{
			libovsdbops.PolicyDirectionKey: string(libovsdbutil.ACLEgress),
		}), macVRFTransitACLPriority, "inport == "+match, nbdb.ACLActionAllowStateless, nil, libovsdbutil.LportEgress),
	}
}

func (gw *GatewayManager) usesNativeIPVRF() bool {
	return gw.netInfo.TopologyType() == types.Layer3Topology && util.UsesOVNNativeEVPN(gw.netInfo)
}

func (gw *GatewayManager) nativeEVPNTableID() (string, error) {
	vrfName := util.GetNetworkVRFName(gw.netInfo)
	link, err := util.GetNetLinkOps().LinkByName(vrfName)
	if err != nil {
		return "", fmt.Errorf("failed to look up EVPN VRF %s: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return "", fmt.Errorf("EVPN interface %s has type %s, expected VRF", vrfName, link.Type())
	}
	return strconv.FormatUint(uint64(vrf.Table), 10), nil
}

func nativeEVPNRouterOptions(netInfo util.NetInfo, tableID string) map[string]string {
	return map[string]string{
		"dynamic-routing":          "true",
		"dynamic-routing-vrf-id":   tableID,
		"dynamic-routing-vrf-name": util.GetNetworkVRFName(netInfo),
		dynamicRoutingNoLearning:   "true",
	}
}

func (gw *GatewayManager) evpnSwitchName() string {
	return gw.netInfo.GetNetworkScopedName("evpn_" + gw.nodeName)
}

func (gw *GatewayManager) syncIPVRFSwitch(router *nbdb.LogicalRouter, mac net.HardwareAddr, tableID string) error {
	switchName := gw.evpnSwitchName()
	lrp := &nbdb.LogicalRouterPort{Name: types.RouterToSwitchPrefix + switchName}
	if tableID == "" {
		if err := libovsdbops.DeleteLogicalSwitch(gw.nbClient, switchName); err != nil {
			return err
		}
		return libovsdbops.DeleteLogicalRouterPorts(gw.nbClient, router, lrp)
	}

	lrp.MAC = mac.String()
	ipv4, ipv6 := gw.netInfo.IPMode()
	if ipv4 {
		lrp.Networks = append(lrp.Networks, evpnStitchIPv4)
	}
	if ipv6 {
		lrp.Networks = append(lrp.Networks, util.HWAddrToIPv6LLA(mac).String()+"/64")
	}
	// The join and external ports inherit no-learning from the gateway router.
	lrp.Options = map[string]string{dynamicRoutingNoLearning: "false"}
	ops, err := libovsdbops.CreateOrUpdateLogicalRouterPortOps(gw.nbClient, nil, router, lrp, nil)
	if err != nil {
		return err
	}

	svi := evpn.GetEVPNL3SVIName(gw.netInfo)
	sw := &nbdb.LogicalSwitch{
		Name:        switchName,
		ExternalIDs: util.GenerateExternalIDsForSwitchOrRouter(gw.netInfo),
		OtherConfig: nativeEVPNSwitchConfig(gw.netInfo.EVPNVTEPName(), gw.netInfo.EVPNIPVRFVNI(), svi, svi),
	}
	sw.ExternalIDs[types.NodeExternalID] = gw.nodeName
	lsp := &nbdb.LogicalSwitchPort{
		Name:      types.SwitchToRouterPrefix + switchName,
		Type:      "router",
		Addresses: []string{"router"},
		Options:   map[string]string{libovsdbops.RouterPort: lrp.Name},
	}
	ops, err = libovsdbops.CreateOrUpdateLogicalSwitchPortsAndSwitchOps(gw.nbClient, ops, sw, lsp)
	if err != nil {
		return err
	}
	if _, err = libovsdbops.TransactAndCheck(gw.nbClient, ops); err != nil {
		return err
	}

	clusterRouter, err := libovsdbops.GetLogicalRouter(gw.nbClient, &nbdb.LogicalRouter{Name: gw.clusterRouterName})
	if err != nil {
		return err
	}
	options := nativeEVPNRouterOptions(gw.netInfo, tableID)
	if clusterRouter.Options == nil {
		clusterRouter.Options = options
	} else {
		maps.Copy(clusterRouter.Options, options)
	}
	return libovsdbops.CreateOrUpdateLogicalRouter(gw.nbClient, clusterRouter, &clusterRouter.Options)
}
