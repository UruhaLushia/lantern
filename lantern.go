package lantern

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/UruhaLushia/lantern/announce"
	"github.com/UruhaLushia/lantern/device"
	"github.com/UruhaLushia/lantern/dhcpserver"
	"github.com/UruhaLushia/lantern/discovery"
	"github.com/UruhaLushia/lantern/network"
)

var (
	ErrAlreadyStarted      = errors.New("controller has already been started; create a new controller to restart")
	ErrUnsupportedPlatform = errors.New("unsupported gateway platform; Windows IPv4 requires explicit WindowsGateway options")
)

type Options struct {
	WindowsGateway *WindowsGatewayOptions
	Interface      string
	GatewayIPv4    netip.Addr
	GatewayIPv6    netip.Addr
	PollInterval   time.Duration
	Logger         *slog.Logger
	Discovery      discovery.Options
	RA             announce.Options
	DHCP           dhcpserver.Options
	MaxDevices     int
	DeviceStore    *device.Store
}

type Status struct {
	IPv4Gateway IPv4GatewayStatus  `json:"ipv4_gateway"`
	State       string             `json:"state"`
	StartedAt   time.Time          `json:"started_at,omitzero"`
	UpdatedAt   time.Time          `json:"updated_at,omitzero"`
	Network     network.Snapshot   `json:"network"`
	Selection   *network.Selection `json:"selection,omitempty"`
	Problems    []string           `json:"problems,omitempty"`
	Discovery   discovery.Status   `json:"discovery"`
	RA          announce.Status    `json:"ra"`
	DHCP        dhcpserver.Status  `json:"dhcp"`
}

type Controller struct {
	datapath          platformDatapath
	opts              Options
	lifeMu            sync.Mutex
	probeMu           sync.Mutex
	refreshMu         sync.Mutex
	started           bool
	cancel            context.CancelFunc
	done              chan struct{}
	mu                sync.RWMutex
	status            Status
	resources         sync.Mutex
	observer          *discovery.Service
	advertiser        *announce.Service
	dhcp              *dhcpserver.Service
	resourceSelection *network.Selection
	resourceAddresses []netip.Addr
	deviceStore       *device.Store
	cleanupErr        error
	clientRoutes      *network.ClientRoutes
}

func New(opts Options) (*Controller, error) {
	if opts.WindowsGateway != nil {
		copy := *opts.WindowsGateway
		copy.Clients = slices.Clone(copy.Clients)
		opts.WindowsGateway = &copy
		if !copy.LocalIPv4.Is4() || !copy.LocalIPv4.IsGlobalUnicast() || copy.EgressInterface == "" || copy.BatchSize < 0 || copy.BatchSize > 16 {
			return nil, errors.New("Windows gateway requires a LAN IPv4, an explicit egress interface and batch size 0..16")
		}
	}
	if opts.Interface == "" {
		opts.Interface = "auto"
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 10 * time.Second
	}
	if opts.PollInterval < time.Second || opts.PollInterval > time.Hour {
		return nil, errors.New("PollInterval must be between 1s and 1h")
	}
	for _, v := range []struct {
		name string
		addr netip.Addr
		ipv4 bool
	}{
		{"GatewayIPv4", opts.GatewayIPv4, true}, {"GatewayIPv6", opts.GatewayIPv6, false},
	} {
		if !v.addr.IsValid() {
			continue
		}
		if v.addr.Is4() != v.ipv4 || v.addr.Is4In6() || v.addr.IsUnspecified() || v.addr.IsMulticast() || v.addr.IsLoopback() || v.addr == netip.MustParseAddr("255.255.255.255") {
			return nil, fmt.Errorf("%s must be a unicast address of the matching family", v.name)
		}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if (opts.RA.Enabled || opts.DHCP.Enabled) && !opts.Discovery.Enabled {
		return nil, errors.New("RA/DHCP require passive discovery to observe upstream announcements")
	}
	var err error
	opts.RA, err = opts.RA.Normalize()
	if err != nil {
		return nil, err
	}
	opts.DHCP, err = opts.DHCP.Normalize()
	if err != nil {
		return nil, err
	}
	if opts.Discovery.AddressTTL == 0 {
		opts.Discovery.AddressTTL = 10 * time.Minute
	}
	if opts.Discovery.DeviceTTL == 0 {
		opts.Discovery.DeviceTTL = 24 * time.Hour
	}
	if opts.Discovery.AddressTTL < time.Second || opts.Discovery.DeviceTTL < time.Second {
		return nil, errors.New("discovery lifetimes must be at least 1s")
	}
	if opts.MaxDevices < 0 || opts.MaxDevices > 65536 {
		return nil, errors.New("MaxDevices must be between 0 and 65536")
	}
	store := opts.DeviceStore
	if store == nil {
		store = device.NewStore(opts.MaxDevices)
	}
	return &Controller{opts: opts, deviceStore: store, done: make(chan struct{}), status: Status{State: "idle"}}, nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	if c.started {
		return ErrAlreadyStarted
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePlatform(c.opts); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel, c.started = cancel, true
	c.mu.Lock()
	c.status.StartedAt = time.Now().UTC()
	c.mu.Unlock()
	c.refresh()
	go c.loop(runCtx)
	return nil
}

func (c *Controller) Run(ctx context.Context) error {
	if err := c.Start(ctx); err != nil {
		return err
	}
	<-c.done
	return c.stoppedError()
}

func (c *Controller) Stop(ctx context.Context) error {
	c.lifeMu.Lock()
	if !c.started {
		c.lifeMu.Unlock()
		return nil
	}
	c.cancel()
	c.lifeMu.Unlock()
	select {
	case <-c.done:
		return c.stoppedError()
	default:
	}
	select {
	case <-c.done:
		return c.stoppedError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) Done() <-chan struct{} { return c.done }

func (c *Controller) Status() Status {
	c.mu.RLock()
	s := c.status
	s.Discovery = s.Discovery.Clone()
	s.DHCP.Leases = slices.Clone(s.DHCP.Leases)
	s.DHCP.Reservations = slices.Clone(s.DHCP.Reservations)
	s.DHCP.GatewayMACs = slices.Clone(s.DHCP.GatewayMACs)
	s.Problems = slices.Clone(s.Problems)
	s.Network.Warnings = slices.Clone(s.Network.Warnings)
	s.Network.DefaultRoutes = slices.Clone(s.Network.DefaultRoutes)
	s.Network.DNS = slices.Clone(s.Network.DNS)
	s.Network.Interfaces = slices.Clone(s.Network.Interfaces)
	for i := range s.Network.Interfaces {
		s.Network.Interfaces[i].Addresses = slices.Clone(s.Network.Interfaces[i].Addresses)
	}
	if s.Selection != nil {
		selection := *s.Selection
		selection.Interface.Addresses = slices.Clone(selection.Interface.Addresses)
		s.Selection = &selection
	}
	c.mu.RUnlock()
	c.resources.Lock()
	if c.datapath != nil {
		s.IPv4Gateway = c.datapath.Snapshot()
	}
	if c.observer != nil {
		s.Discovery = c.observer.Snapshot()
	}
	if c.advertiser != nil {
		s.RA = c.advertiser.Snapshot()
	}
	if c.dhcp != nil {
		s.DHCP = c.dhcp.Snapshot()
	}
	c.resources.Unlock()
	return s
}

func (c *Controller) Devices() []device.Device { return c.deviceStore.Snapshot() }

func (c *Controller) ProbeDHCP(ctx context.Context, timeout time.Duration) (discovery.DHCPProbe, error) {
	if !c.probeMu.TryLock() {
		return discovery.DHCPProbe{}, errors.New("a DHCP probe is already running")
	}
	defer c.probeMu.Unlock()
	c.lifeMu.Lock()
	started := c.started
	c.lifeMu.Unlock()
	if !started {
		return discovery.DHCPProbe{}, errors.New("controller has not started")
	}
	select {
	case <-c.done:
		return discovery.DHCPProbe{}, errors.New("controller has stopped")
	default:
	}
	s := c.Status()
	if s.Selection == nil {
		return discovery.DHCPProbe{}, errors.New("no selected LAN interface")
	}
	ctx, cancel := context.WithCancel(ctx)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-c.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-finished }()
	return discovery.ProbeDHCP(ctx, s.Selection.Interface.Name, timeout)
}

func (c *Controller) ResumeDHCP() error {
	c.resources.Lock()
	defer c.resources.Unlock()
	if c.dhcp == nil {
		return errors.New("DHCP server is not active")
	}
	return c.dhcp.Resume()
}

func (c *Controller) SetDHCPGatewayMACs(macs []string) error {
	c.resources.Lock()
	defer c.resources.Unlock()
	if c.dhcp == nil {
		return errors.New("DHCP server is not active")
	}
	if err := c.dhcp.SetGatewayMACs(macs); err != nil {
		return err
	}
	c.opts.DHCP.GatewayMACs = c.dhcp.Snapshot().GatewayMACs
	c.syncRATargetsLocked()
	return nil
}

func (c *Controller) loop(ctx context.Context) {
	defer close(c.done)
	defer func() {
		c.mu.Lock()
		c.status.State, c.status.UpdatedAt = "stopped", time.Now().UTC()
		c.mu.Unlock()
	}()
	defer func() {
		c.refreshMu.Lock()
		defer c.refreshMu.Unlock()
		c.mu.Lock()
		c.cleanupErr = nil
		c.mu.Unlock()
		c.closeResources()
	}()
	ticker := time.NewTicker(c.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh()
		}
	}
}

func (c *Controller) refresh() {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.refreshLocked()
}

func (c *Controller) refreshLocked() {
	snapshot, err := network.Discover()
	problems := slices.Clone(snapshot.Warnings)
	var selection *network.Selection
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		selected, selectErr := snapshot.Select(c.opts.Interface, c.opts.GatewayIPv4, c.opts.GatewayIPv6)
		if selectErr != nil {
			problems = append(problems, selectErr.Error())
		} else {
			selection = &selected
			if !selected.GatewayIPv4.IsValid() && !selected.GatewayIPv6.IsValid() {
				problems = append(problems, "no on-link upstream default gateway observed; set gateway explicitly if needed")
			}
		}
	}
	c.deviceStore.Expire(time.Now(), c.opts.Discovery.DeviceTTL)
	if selection != nil {
		problems = append(problems, c.reconcile(*selection, snapshot.Interfaces)...)
	} else {
		c.closeResources()
	}
	c.mu.Lock()
	changed := !reflect.DeepEqual(c.status.Problems, problems) || !reflect.DeepEqual(c.status.Selection, selection)
	c.status.Network, c.status.Selection, c.status.Problems = snapshot, selection, problems
	c.status.UpdatedAt, c.status.State = time.Now().UTC(), "running"
	if len(problems) > 0 {
		c.status.State = "degraded"
	}
	c.mu.Unlock()
	if changed {
		c.opts.Logger.Info("network observation changed", "problems", problems, "selection", selection)
	}
}

func (c *Controller) reconcile(selected network.Selection, interfaces []network.Interface) []string {
	c.resources.Lock()
	defer c.resources.Unlock()
	var addresses []netip.Addr
	for _, iface := range interfaces {
		for _, prefix := range iface.Addresses {
			addresses = append(addresses, prefix.Addr())
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	addresses = slices.Compact(addresses)
	if !reflect.DeepEqual(c.resourceSelection, &selected) || !slices.Equal(c.resourceAddresses, addresses) {
		c.closeResourcesLocked()
		c.resourceSelection, c.resourceAddresses = &selected, addresses
	}
	var problems []string
	var err error
	if c.datapath != nil && c.datapath.Ready() != nil {
		c.closeResourcesLocked()
	}
	if c.datapath == nil {
		c.datapath, err = startPlatformDatapath(selected, c.opts)
		if err != nil {
			return []string{"IPv4 forwarding: " + err.Error()}
		}
	}
	iface, err := net.InterfaceByIndex(selected.Interface.Index)
	if err != nil {
		return []string{err.Error()}
	}

	if c.opts.Discovery.Enabled && c.observer == nil {
		c.observer, err = startPlatformDiscovery(context.Background(), *iface, c.opts.Discovery, c.deviceStore, c.datapath)
		if err != nil {
			problems = append(problems, "discovery: "+err.Error())
		}
	}
	if c.observer != nil {
		s := c.observer.Snapshot()
		problems = append(problems, s.Problems...)
		if !s.Running {
			c.closeResourcesLocked()
			problems = append(problems, "discovery stopped; retrying on next poll")
		}
	}
	if c.opts.RA.Enabled && !selected.GatewayIPv6.IsValid() {
		problems = append(problems, "RA: 等待 IPv6 主路由，暂不宣告")
	}
	if c.opts.RA.Enabled && selected.GatewayIPv6.IsValid() && c.observer != nil && c.advertiser == nil {
		observer := c.observer
		raOpts := c.opts.RA
		if c.opts.DHCP.Enabled {
			raOpts.UnicastOnly = true
			raOpts.Targets = c.raTargetsLocked()
		}
		c.advertiser, err = announce.Start(context.Background(), *iface, raOpts, func() announce.Upstream {
			if err := network.ForwardingReady(iface.Name, false, true); err != nil {
				return announce.Upstream{Reason: err.Error()}
			}
			for _, r := range observer.Snapshot().Routers {
				if r.Address.WithZone("") == selected.GatewayIPv6.WithZone("") {
					return announce.Upstream{Router: r, Ready: true}
				}
			}
			return announce.Upstream{Router: discovery.Router{Address: selected.GatewayIPv6}, Reason: "waiting for RA from selected physical upstream"}
		})
		if err != nil {
			problems = append(problems, "RA: "+err.Error())
		} else {
			c.observer.SetRSHandler(c.advertiser.Solicited)
		}
	}
	if c.opts.DHCP.Enabled && c.observer != nil && c.dhcp == nil {
		if c.clientRoutes == nil {
			c.clientRoutes, err = network.NewClientRoutes(selected.Interface)
			if err != nil {
				return append(problems, "client routing: "+err.Error())
			}
		}
		dhcpOpts := c.opts.DHCP
		if c.datapath != nil {
			datapath := c.datapath
			previousHook := dhcpOpts.OnLease
			dhcpOpts.OnLease = func(l dhcpserver.Lease, selected bool) error {
				if previousHook != nil {
					if err := previousHook(l, selected); err != nil {
						return err
					}
				}
				return datapath.SetLease(l.MAC, l.IP, l.ExpiresAt, selected && l.State == "bound")
			}
		}
		c.dhcp, err = dhcpserver.Start(context.Background(), selected, dhcpOpts, c.observer, c.deviceStore, func() error {
			if c.datapath != nil {
				return c.datapath.Ready()
			}
			return network.ForwardingReady(iface.Name, true, false)
		})
		if err != nil {
			problems = append(problems, "DHCP: "+err.Error())
		}
	}
	if c.dhcp != nil {
		if err := c.syncClientRoutesLocked(); err != nil {
			problems = append(problems, "client routing: "+err.Error())
		}
		if s := c.dhcp.Snapshot(); s.PausedReason != "" {
			problems = append(problems, "DHCP: "+s.PausedReason)
		}
	}
	if c.advertiser != nil {
		c.syncRATargetsLocked()
		s := c.advertiser.Snapshot()
		if s.SuspendedReason != "" {
			problems = append(problems, "RA: "+s.SuspendedReason)
		}
		if s.LastError != "" {
			problems = append(problems, "RA: "+s.LastError)
		}
	}
	return problems
}

func (c *Controller) raTargetsLocked() []netip.Addr {
	var targets []netip.Addr
	if c.resourceSelection == nil {
		return targets
	}
	for _, d := range c.deviceStore.Snapshot() {
		if d.Interface != c.resourceSelection.Interface.Name || !slices.Contains(c.opts.DHCP.GatewayMACs, d.MAC) {
			continue
		}
		for _, a := range d.Addresses {
			ip := a.IP.WithZone("")
			if ip.Is6() && ip.IsLinkLocalUnicast() && (len(c.opts.RA.Targets) == 0 || slices.Contains(c.opts.RA.Targets, ip)) {
				targets = append(targets, ip)
			}
		}
	}
	slices.SortFunc(targets, netip.Addr.Compare)
	return slices.Compact(targets)
}

func (c *Controller) syncRATargetsLocked() {
	if c.advertiser != nil && c.opts.DHCP.Enabled {
		c.advertiser.SetTargets(c.raTargetsLocked())
	}
}

func (c *Controller) closeResources() {
	c.resources.Lock()
	defer c.resources.Unlock()
	c.closeResourcesLocked()
}
func (c *Controller) closeResourcesLocked() {
	if c.dhcp != nil {
		if err := c.dhcp.Close(); err != nil {
			c.opts.Logger.Error("stop DHCP", "error", err)
			c.recordCleanupError(err)
		}
		c.mu.Lock()
		c.status.DHCP = c.dhcp.Snapshot()
		c.mu.Unlock()
		c.dhcp = nil
	}
	if c.advertiser != nil {
		if err := c.closeAdvertiserLocked(); err != nil {
			c.opts.Logger.Error("withdraw RA", "error", err)
			c.recordCleanupError(err)
		}
	}
	if c.observer != nil {
		if err := c.observer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.recordCleanupError(err)
		}
		c.mu.Lock()
		c.status.Discovery = c.observer.Snapshot()
		c.mu.Unlock()
		c.observer = nil
	}
	if c.datapath != nil {
		if err := c.datapath.Close(); err != nil {
			c.recordCleanupError(err)
		}
		c.mu.Lock()
		c.status.IPv4Gateway = c.datapath.Snapshot()
		c.mu.Unlock()
		c.datapath = nil
	}
	c.resourceSelection, c.resourceAddresses = nil, nil
	if c.clientRoutes != nil {
		if err := c.clientRoutes.Close(); err != nil {
			c.recordCleanupError(err)
		} else {
			c.clientRoutes = nil
		}
	}
}

func (c *Controller) syncClientRoutesLocked() error {
	if c.clientRoutes == nil || c.dhcp == nil || c.resourceSelection == nil {
		return nil
	}
	var addresses []netip.Addr
	clients := make(map[string]bool)
	now := time.Now()
	for _, lease := range c.dhcp.Snapshot().Leases {
		if lease.State == "bound" && lease.ExpiresAt.After(now) {
			clients[lease.MAC] = true
			addresses = append(addresses, lease.IP)
		}
	}
	for _, d := range c.deviceStore.Snapshot() {
		if d.Interface != c.resourceSelection.Interface.Name || !clients[d.MAC] {
			continue
		}
		for _, address := range d.Addresses {
			if address.IP.Is6() && c.datapath == nil {
				addresses = append(addresses, address.IP)
			}
		}
	}
	return c.clientRoutes.Sync(addresses)
}

func (c *Controller) recordCleanupError(err error) {
	c.mu.Lock()
	c.cleanupErr = errors.Join(c.cleanupErr, err)
	c.mu.Unlock()
}
func (c *Controller) stoppedError() error { c.mu.RLock(); defer c.mu.RUnlock(); return c.cleanupErr }
