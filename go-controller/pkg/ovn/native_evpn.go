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

	utilnet "k8s.io/utils/net"

	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
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
	if native {
		legacyPort := &nbdb.LogicalSwitchPort{Name: util.GetMACVRFPortName(sw.Name)}
		return libovsdbops.DeleteLogicalSwitchPorts(oc.nbClient, sw, legacyPort)
	}
	return nil
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
