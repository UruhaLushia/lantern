package lantern

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/UruhaLushia/lantern/announce"
	"github.com/UruhaLushia/lantern/dhcpserver"
	"github.com/UruhaLushia/lantern/network"
)

type GatewayOptions struct {
	Interface   string
	GatewayIPv4 netip.Addr
	GatewayIPv6 netip.Addr
	RA          announce.Options
	DHCP        dhcpserver.Options
}

func (c *Controller) ConfigureGateway(opts GatewayOptions) error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	if !c.started {
		return errors.New("controller has not started")
	}
	select {
	case <-c.done:
		return errors.New("controller has stopped")
	default:
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.resources.Lock()
	previous := c.opts
	next := previous
	next.Interface, next.GatewayIPv4, next.GatewayIPv6 = opts.Interface, opts.GatewayIPv4, opts.GatewayIPv6
	next.RA, next.DHCP = opts.RA, opts.DHCP
	validated, err := New(next)
	if err == nil {
		next = validated.opts
		err = validatePlatform(next)
	}
	if err == nil {
		var snapshot network.Snapshot
		snapshot, err = network.Discover()
		if err == nil {
			_, err = snapshot.Select(next.Interface, next.GatewayIPv4, next.GatewayIPv6)
		}
	}
	if err != nil {
		// Validation has changed no resources. In particular, do not reconcile
		// (and potentially open native handles) for a rejected configuration.
		c.resources.Unlock()
		return err
	}
	err = c.configureGatewayLocked(next)
	c.resources.Unlock()
	if err == nil {
		c.refreshLocked()
		err = gatewayConfigurationError(next, c.Status())
	}
	if err != nil {
		c.resources.Lock()
		rollbackErr := c.configureGatewayLocked(previous)
		c.resources.Unlock()
		c.refreshLocked()
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func gatewayConfigurationError(opts Options, s Status) error {
	// A running DHCP socket alone does not establish that Windows can forward
	// the leases it advertises. Check static-client configurations as well.
	if opts.WindowsGateway != nil && !s.IPv4Gateway.Running {
		return fmt.Errorf("gateway configuration could not be applied: IPv4 datapath is not running (last error: %s; problems: %v)", s.IPv4Gateway.LastError, s.Problems)
	}
	if (opts.DHCP.Enabled && !s.DHCP.Running) ||
		(opts.RA.Enabled && s.Selection != nil && s.Selection.GatewayIPv6.IsValid() && !s.RA.Enabled) {
		return fmt.Errorf("gateway configuration could not be applied: %v", s.Problems)
	}
	return nil
}

func (c *Controller) configureGatewayLocked(next Options) error {
	var errs []error
	if !reflect.DeepEqual(c.opts.RA, next.RA) {
		errs = append(errs, c.closeAdvertiserLocked())
	}
	if !reflect.DeepEqual(c.opts.DHCP, next.DHCP) && c.dhcp != nil {
		errs = append(errs, c.dhcp.Close())
		c.mu.Lock()
		c.status.DHCP = c.dhcp.Snapshot()
		c.mu.Unlock()
		c.dhcp = nil
		if c.datapath != nil {
			c.datapath.ClearLeases()
		}
	}
	c.opts.Interface, c.opts.GatewayIPv4, c.opts.GatewayIPv6 = next.Interface, next.GatewayIPv4, next.GatewayIPv6
	c.opts.RA, c.opts.DHCP = next.RA, next.DHCP
	return errors.Join(errs...)
}

func (c *Controller) closeAdvertiserLocked() error {
	if c.advertiser == nil {
		return nil
	}
	if c.observer != nil {
		c.observer.SetRSHandler(nil)
	}
	err := c.advertiser.Close()
	c.mu.Lock()
	c.status.RA = c.advertiser.Snapshot()
	c.status.RA.Enabled = false
	c.status.RA.SuspendedReason = ""
	c.mu.Unlock()
	c.advertiser = nil
	return err
}
