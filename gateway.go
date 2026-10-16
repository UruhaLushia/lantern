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
		var snapshot network.Snapshot
		snapshot, err = network.Discover()
		if err == nil {
			_, err = snapshot.Select(next.Interface, next.GatewayIPv4, next.GatewayIPv6)
		}
	}
	if err == nil {
		err = c.configureGatewayLocked(next)
	}
	c.resources.Unlock()
	if err == nil {
		c.refreshLocked()
		s := c.Status()
		if (next.DHCP.Enabled && !s.DHCP.Running) ||
			(next.RA.Enabled && s.Selection != nil && s.Selection.GatewayIPv6.IsValid() && !s.RA.Enabled) {
			err = fmt.Errorf("gateway configuration could not be applied: %v", s.Problems)
		}
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
