// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package ovn

import (
	"net"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Native EVPN IP-VRF", func() {
	It("reconciles the gateway switch and keeps route learning on its stitch port", func() {
		Expect(config.PrepareTestConfig()).To(Succeed())
		config.Gateway.Mode = config.GatewayModeShared
		config.IPv6Mode = true
		netInfo := dummyPrimaryLayer3EVPNCUDN("192.168.0.0/16,fd00:1::/48/64", "")
		netInfo.evpn = &ovncnitypes.EVPNConfig{
			VTEP: "fabric", IPVRF: &ovncnitypes.VRFConfig{VNI: 20101, VID: 3},
		}
		network, err := util.NewNetInfo(netInfo.netconf())
		Expect(err).NotTo(HaveOccurred())
		clusterRouter := &nbdb.LogicalRouter{Name: network.GetNetworkScopedClusterRouterName(), Options: map[string]string{"mcast_relay": "true"}}
		nbClient, cleanup, err := libovsdbtest.NewNBTestHarness(libovsdbtest.TestSetup{
			NBData: []libovsdbtest.TestData{clusterRouter},
		}, nil)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(cleanup.Cleanup)

		gw := NewGatewayManager(nodeName, "", nil, nbClient, network, nil, nil, nil)
		mac, err := net.ParseMAC("02:00:00:00:00:01")
		Expect(err).NotTo(HaveOccurred())
		gatewayConfig := &GatewayConfig{annoConfig: &util.L3GatewayConfig{
			MACAddress: mac, ChassisID: "node-chassis", IPAddresses: dummyJoinIPs(),
		}}
		gatewayRouter, err := gw.createGWRouter(gatewayConfig, "1042")
		Expect(err).NotTo(HaveOccurred())
		Expect(gw.syncIPVRFSwitch(gatewayRouter, mac, "1042")).To(Succeed())
		Expect(gw.syncIPVRFSwitch(gatewayRouter, mac, "1042")).To(Succeed())

		Expect(gatewayRouter.Options).To(HaveKeyWithValue(dynamicRoutingNoLearning, "true"))
		sw, err := libovsdbops.GetLogicalSwitch(nbClient, &nbdb.LogicalSwitch{Name: gw.evpnSwitchName()})
		Expect(err).NotTo(HaveOccurred())
		Expect(sw.OtherConfig).To(HaveKeyWithValue("dynamic-routing-vni", "20101"))
		Expect(sw.ExternalIDs).To(HaveKeyWithValue(types.NodeExternalID, nodeName))
		Expect(sw.Ports).To(HaveLen(1))
		lrp, err := libovsdbops.GetLogicalRouterPort(nbClient, &nbdb.LogicalRouterPort{Name: types.RouterToSwitchPrefix + sw.Name})
		Expect(err).NotTo(HaveOccurred())
		Expect(lrp.MAC).To(Equal(mac.String()))
		Expect(lrp.Networks).To(ConsistOf("169.254.255.1/32", "fe80::ff:fe00:1/64"))
		Expect(lrp.Options).To(HaveKeyWithValue(dynamicRoutingNoLearning, "false"))
		clusterRouter, err = libovsdbops.GetLogicalRouter(nbClient, clusterRouter)
		Expect(err).NotTo(HaveOccurred())
		Expect(clusterRouter.Options).To(HaveKeyWithValue("dynamic-routing-vrf-id", "1042"))
		Expect(clusterRouter.Options).To(HaveKeyWithValue("mcast_relay", "true"))

		Expect(gw.syncIPVRFSwitch(gatewayRouter, mac, "")).To(Succeed())
		_, err = libovsdbops.GetLogicalSwitch(nbClient, &nbdb.LogicalSwitch{Name: sw.Name})
		Expect(err).To(MatchError(libovsdbclient.ErrNotFound))
		_, err = libovsdbops.GetLogicalRouterPort(nbClient, &nbdb.LogicalRouterPort{Name: lrp.Name})
		Expect(err).To(MatchError(libovsdbclient.ErrNotFound))
	})
})
