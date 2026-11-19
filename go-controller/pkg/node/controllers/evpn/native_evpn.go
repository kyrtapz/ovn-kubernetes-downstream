// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package evpn

import (
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	vtepv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/vtep/v1"
	libovsdbops "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

const (
	ovnEVPNLocalIP    = "ovn-evpn-local-ip"
	ovnEVPNVXLANPorts = "ovn-evpn-vxlan-ports"

	// In shared gateway mode the kernel VXLAN device is for FRR control
	// plane state. OVS must receive the fabric's VXLAN traffic on UDP 4789.
	nativeEVPNHostVXLANPort = 64789
)

func hostVXLANPort() int {
	if config.Gateway.Mode == config.GatewayModeShared {
		return nativeEVPNHostVXLANPort
	}
	return config.DefaultVXLANPort
}

func hybridOverlayVXLANConflict() bool {
	port := config.HybridOverlay.VXLANPort
	return config.HybridOverlay.Enabled && (port == config.DefaultVXLANPort || port == uint(hostVXLANPort()))
}

func (c *Controller) syncNativeEVPN() error {
	sources := sets.New[string]()
	if config.Gateway.Mode == config.GatewayModeShared && !hybridOverlayVXLANConflict() {
		vteps, err := c.watchFactory.VTEPInformer().Lister().List(labels.Everything())
		if err != nil {
			return fmt.Errorf("failed to list VTEPs for native EVPN: %w", err)
		}
		annotations, err := c.getVTEPsAnnotation()
		if err != nil {
			return err
		}
		vtepIPs := make(map[string][]string, len(vteps))
		for _, vtep := range vteps {
			if vtep.Spec.Mode == vtepv1.VTEPModeUnmanaged {
				vtepIPs[vtep.Name] = annotations[vtep.Name].IPs
			}
		}
		err = c.networkMgr.DoWithLock(func(network util.NetInfo) error {
			for _, ip := range vtepIPs[network.EVPNVTEPName()] {
				for _, vni := range []int32{network.EVPNMACVRFVNI(), network.EVPNIPVRFVNI()} {
					if vni != 0 {
						sources.Insert(fmt.Sprintf("%d-%s", vni, ip))
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	if sources.Len() == 0 {
		return libovsdbops.RemoveOpenvSwitchExternalIDs(c.ovsClient, ovnEVPNLocalIP, ovnEVPNVXLANPorts)
	}
	return libovsdbops.UpdateOpenvSwitchExternalIDs(c.ovsClient, map[string]string{
		ovnEVPNLocalIP:    strings.Join(sets.List(sources), ","),
		ovnEVPNVXLANPorts: strconv.Itoa(config.DefaultVXLANPort),
	})
}
