package miner

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"os"

	"golang.org/x/net/context"

	"net"

	"github.com/ccding/go-stun/stun"
	log "github.com/noxiouz/zapctx/ctxlog"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/sonm-io/core/insonmnia/hardware"
	"github.com/sonm-io/core/insonmnia/resource"
	pb "github.com/sonm-io/core/proto"
	"github.com/sonm-io/core/util"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

type MinerBuilder struct {
	ctx       context.Context
	cfg       Config
	hardware  hardware.HardwareInfo
	publicIPs []string
	nat       stun.NATType
	ovs       Overseer
	uuid      string
	ssh       SSH
}

func (b *MinerBuilder) Context(ctx context.Context) *MinerBuilder {
	b.ctx = ctx
	return b
}

func (b *MinerBuilder) Config(config Config) *MinerBuilder {
	b.cfg = config
	return b
}

func (b *MinerBuilder) Hardware(hardware hardware.HardwareInfo) *MinerBuilder {
	b.hardware = hardware
	return b
}

func (b *MinerBuilder) AddPublicIP(ip net.IP) *MinerBuilder {
	b.publicIPs = append(b.publicIPs, ip.String())
	return b
}

func (b *MinerBuilder) Overseer(ovs Overseer) *MinerBuilder {
	b.ovs = ovs
	return b
}

func (b *MinerBuilder) UUID(uuid string) *MinerBuilder {
	b.uuid = uuid
	return b
}

func (b *MinerBuilder) SSH(ssh SSH) *MinerBuilder {
	b.ssh = ssh
	return b
}

func (b *MinerBuilder) Build() (miner *Miner, err error) {
	if b.ctx == nil {
		b.ctx = context.Background()
	}

	if b.cfg == nil {
		return nil, errors.New("config is mandatory for MinerBuilder")
	}

	log.G(b.ctx).Debug("building a miner", zap.Any("config", b.cfg))

	if b.hardware == nil {
		b.hardware = hardware.New()
	}

	if err := b.resolvePublicIPs(); err != nil {
		return nil, err
	}

	log.G(b.ctx).Info("Discovered public IPs",
		zap.Any("public IPs", b.publicIPs),
		zap.Any("nat", b.nat))

	ctx, cancel := context.WithCancel(b.ctx)
	if b.ovs == nil {
		b.ovs, err = NewOverseer(ctx, b.cfg.GPU())
		if err != nil {
			cancel()
			return nil, err
		}
	}

	if len(b.uuid) == 0 {
		b.uuid = uuid.New()
	}

	hardwareInfo, err := b.hardware.Info()

	if b.ssh == nil && b.cfg.SSH() != nil {
		b.ssh, err = NewSSH(b.cfg.SSH())
		if err != nil {
			cancel()
			return nil, err
		}
	}

	if err != nil {
		cancel()
		return nil, err
	}

	log.G(ctx).Info("collected Hardware info", zap.Any("hardware", hardwareInfo))

	var (
		creds       credentials.TransportCredentials
		certRotator util.HitlessCertRotator
	)
	if os.Getenv("GRPC_INSECURE") == "" {
		var (
			ethKey  *ecdsa.PrivateKey
			TLSConf *tls.Config
		)
		if b.cfg.ETH() == nil || b.cfg.ETH().PrivateKey == "" {
			cancel()
			return nil, fmt.Errorf("either PrivateKey or GRPC_INSECURE environment variable must be set")
		}
		ethKey, err = ethcrypto.HexToECDSA(b.cfg.ETH().PrivateKey)
		if err != nil {
			cancel()
			return nil, err
		}
		// The rotator will be stopped by ctx
		certRotator, TLSConf, err = util.NewHitlessCertRotator(ctx, ethKey)
		if err != nil {
			return nil, err
		}
		creds = util.NewTLS(TLSConf)
	}
	grpcServer := util.MakeGrpcServer(creds)

	cgroup, cGroupManager, err := makeCgroupManager(b.cfg.HubResources())
	if err != nil {
		cancel()
		return nil, err
	}

	if !platformSupportCGroups && b.cfg.HubResources() != nil {
		log.G(ctx).Warn("your platform does not support CGroup, but the config has resources section")
	}

	m := &Miner{
		ctx:        ctx,
		cancel:     cancel,
		grpcServer: grpcServer,
		ovs:        b.ovs,

		name:      b.uuid,
		hardware:  hardwareInfo,
		resources: resource.NewPool(hardwareInfo),

		publicIPs:  b.publicIPs,
		natType:    b.nat,
		hubAddress: b.cfg.HubEndpoint(),

		rl:             newReverseListener(1),
		containers:     make(map[string]*ContainerInfo),
		statusChannels: make(map[int]chan bool),
		nameMapping:    make(map[string]string),

		controlGroup:  cgroup,
		cGroupManager: cGroupManager,
		ssh:           b.ssh,

		connectedHubs: make(map[string]struct{}),

		certRotator: certRotator,
		creds:       creds,
	}

	pb.RegisterMinerServer(grpcServer, m)
	return m, nil
}

func (b *MinerBuilder) resolvePublicIPs() error {
	// PublicIPs might have been set via builder's API.
	if b.publicIPs != nil {
		return nil
	}

	// Discover IP if we're behind a NAT.
	if b.cfg.Firewall() != nil {
		log.G(b.ctx).Debug("Discovering public IP address with NAT type, this might be slow")

		client := stun.NewClient()
		if b.cfg.Firewall().Server != "" {
			client.SetServerAddr(b.cfg.Firewall().Server)
		}

		nat, addr, err := client.Discover()
		if err != nil {
			return err
		}

		b.publicIPs = append(b.publicIPs, addr.IP())
		b.nat = nat

		return nil
	}

	b.nat = stun.NATNone

	// Use publicIPs from config (if provided).
	endpoints := b.cfg.PublicIPs()
	if len(endpoints) > 0 {
		b.publicIPs = endpoints
		return nil
	}

	// Scan interfaces if there's no config and no NAT.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to parse publicIPs from interfaces: %s", err)
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return fmt.Errorf("failed to parse publicIPs from interface %s: %s", i.Name, err)
		}

		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPAddr); ok {
				if ip != nil && ip.String() != "127.0.0.1" {
					b.publicIPs = append(b.publicIPs, ip.String())
				}
			}
		}

		// TODO: sort and filter found IPs.
	}

	if len(endpoints) > 0 {
		return nil
	}

	return errors.New("failed to resolve publicIPs")
}

func makeCgroupManager(cfg *ResourcesConfig) (cGroup, cGroupManager, error) {
	if !platformSupportCGroups || cfg == nil {
		return newNilCgroupManager()
	}
	return newCgroupManager(cfg.Cgroup, cfg.Resources)
}

func NewMinerBuilder(cfg Config) MinerBuilder {
	b := MinerBuilder{}
	b.Config(cfg)
	return b
}
