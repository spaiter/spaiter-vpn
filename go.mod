module github.com/spaiter/spaiter-vpn

go 1.25.6

require (
	fyne.io/systray v1.11.1-0.20250812065214-4856ac3adc3c
	github.com/9seconds/mtg/v2 v2.1.7
	github.com/Kodeworks/golang-image-ico v0.0.0-20141118225523-73f0f4cfade9
	github.com/anthropics/anthropic-sdk-go v1.26.0
	github.com/atotto/clipboard v0.1.4
	github.com/caddyserver/certmagic v0.25.3-0.20260421143802-60d9d8b415d6
	github.com/caddyserver/zerossl v0.1.5
	github.com/cilium/ebpf v0.20.0
	github.com/coder/websocket v1.8.14
	github.com/creack/pty v1.1.24
	github.com/cretz/bine v0.2.0
	github.com/database64128/tfo-go/v2 v2.3.2
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e
	github.com/docker/docker v27.5.1+incompatible
	github.com/docker/go-connections v0.8.2
	github.com/enfein/mieru/v3 v3.27.0
	github.com/fogleman/gg v1.3.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-chi/render v1.0.3
	github.com/godbus/dbus/v5 v5.2.2
	github.com/gofrs/uuid/v5 v5.4.0
	github.com/google/go-tpm v0.9.4
	github.com/gorilla/csrf v1.7.3
	github.com/hashicorp/go-hclog v1.6.2
	github.com/hashicorp/raft v1.7.2
	github.com/hashicorp/raft-boltdb/v2 v2.3.1
	github.com/hiddify/hmrd_multi_resolver_dns v0.0.0-20260429114007-8d809dc33d0e
	github.com/illarion/gonotify/v3 v3.0.2
	github.com/insomniacslk/dhcp v0.0.0-20260220084031-5adc3eb26f91
	github.com/jellydator/ttlcache/v3 v3.4.0
	github.com/jessevdk/go-flags v1.6.1
	github.com/jsimonetti/rtnetlink v1.4.0
	github.com/keybase/go-keychain v0.0.1
	github.com/kortschak/wol v0.0.0-20200729010619-da482cc4850a
	github.com/libdns/acmedns v0.5.0
	github.com/libdns/alidns v1.0.6
	github.com/libdns/cloudflare v0.2.2
	github.com/libdns/libdns v1.1.1
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mdlayher/genetlink v1.3.2
	github.com/mdlayher/netlink v1.9.0
	github.com/mdlayher/sdnotify v1.0.0
	github.com/metacubex/utls v1.8.4
	github.com/mholt/acmez/v3 v3.1.6
	github.com/miekg/dns v1.1.72
	github.com/openai/openai-go/v3 v3.26.0
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/pires/go-proxyproto v0.8.1
	github.com/pkg/sftp v1.13.10
	github.com/prometheus/client_golang v1.23.0
	github.com/quic-go/masque-go v0.4.0
	github.com/sagernet/asc-go v0.0.0-20241217030726-d563060fe4e1
	github.com/sagernet/bbolt v0.0.0-20231014093535-ea5cb2fe9f0a
	github.com/sagernet/cors v1.2.1
	github.com/sagernet/cronet-go v0.0.0-20260620140045-05ab0dc17597
	github.com/sagernet/cronet-go/all v0.0.0-20260620140045-05ab0dc17597
	github.com/sagernet/fswatch v0.1.2
	github.com/sagernet/gliderssh v0.3.4-0.20260531100337-2194faca5648
	github.com/sagernet/gomobile v0.1.12
	github.com/sagernet/gvisor v0.0.0-20250811.0-sing-box-mod.1
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a
	github.com/sagernet/nftables v0.3.0-mod.3
	github.com/sagernet/quic-go v0.59.0-sing-box-mod.4
	github.com/sagernet/sing v0.8.12-0.20260702081104-2ded2af32d3d
	github.com/sagernet/sing-cloudflared v0.1.3-0.20260706062323-d9787e794aa3
	github.com/sagernet/sing-mux v0.3.5
	github.com/sagernet/sing-quic v0.6.4-0.20260709034545-e23afe1172dc
	github.com/sagernet/sing-shadowsocks v0.2.8
	github.com/sagernet/sing-shadowsocks2 v0.2.1
	github.com/sagernet/sing-tun v0.8.12-0.20260711072757-9e647fcd6b38
	github.com/sagernet/sing-usbip v0.0.0-20260616101517-efb91521eddb
	github.com/sagernet/smux v1.5.50-sing-box-mod.1
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/spf13/cobra v1.10.2
	github.com/spyzhov/ajson v0.9.6
	github.com/stretchr/testify v1.11.1
	github.com/tidwall/gjson v1.18.0
	github.com/toqueteos/webbrowser v1.2.0
	github.com/vishvananda/netlink v1.3.1-0.20240922070040-084abd93d350
	github.com/vishvananda/netns v0.0.5
	github.com/yosida95/uritemplate/v3 v3.0.2
	go.uber.org/goleak v1.3.0
	go.uber.org/zap v1.27.1
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.53.0
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93
	golang.org/x/mod v0.36.0
	golang.org/x/net v0.56.0
	golang.org/x/sync v0.21.0
	golang.org/x/sys v0.46.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
	howett.net/plist v1.0.1
	lukechampine.com/blake3 v1.4.1
	modernc.org/sqlite v1.46.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/go-telegram/bot v1.27.0
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-metrics v0.5.4 // indirect
	github.com/hashicorp/go-msgpack/v2 v2.1.2 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/morikuni/aec v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	golang.org/x/image v0.27.0 // indirect
)

require (
	github.com/AdguardTeam/golibs v0.32.7
	github.com/ameshkov/dnsstamps v1.0.3
	github.com/biter777/countries v1.7.5
	github.com/dunglas/httpsfv v1.1.0
	github.com/quic-go/quic-go v0.60.0
)

require (
	filippo.io/age v1.2.1
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/akutz/memconn v0.1.0
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa
	github.com/andybalholm/brotli v1.2.0
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/coreos/go-iptables v0.7.1-0.20240112124308-65c67c9f46e6
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa
	github.com/dgrijalva/jwt-go/v4 v4.0.0-preview1 // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/florianl/go-nfqueue/v2 v2.0.2 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/gaissmai/bart v0.18.0
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced
	github.com/go-ole/go-ole v1.3.0
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.2.1-0.20240414091927-5e242ec57806
	github.com/google/uuid v1.6.0
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0
	github.com/huin/goupnp v1.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.18.3
	github.com/klauspost/cpuid/v2 v2.3.0
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/mdlayher/socket v0.5.1
	github.com/mitchellh/go-ps v1.0.0
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/prometheus-community/pro-bing v0.4.0
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/safchain/ethtool v0.3.0
	github.com/sagernet/cronet-go/lib/android_386 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/android_amd64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/android_arm v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/android_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/darwin_amd64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/ios_amd64_simulator v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64_simulator v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_386 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_386_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_arm v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_arm_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_mips64le v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64_musl v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/tvos_amd64_simulator v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64_simulator v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/windows_amd64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/sagernet/cronet-go/lib/windows_arm64 v0.0.0-20260620135226-def9ff0fb992 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tailscale/certstore v0.1.1-0.20231202035212-d3fa0460f47e
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745
	golang.org/x/oauth2 v0.34.0
	golang.org/x/term v0.44.0
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/time v0.14.0
	golang.org/x/tools v0.45.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	gopkg.in/yaml.v3 v3.0.1
	zombiezen.com/go/capnproto2 v2.18.2+incompatible // indirect
)

require (
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/flynn/noise v1.1.0
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/mattn/go-isatty v0.0.20
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/panjf2000/ants/v2 v2.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/refraction-networking/utls v1.8.2
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sirupsen/logrus v1.9.4
	github.com/things-go/go-socks5 v0.1.1
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/tylertreat/BoomFilters v0.0.0-20210315201527-1a82519a3e43 // indirect
	github.com/xtaci/kcp-go/v5 v5.6.70
	github.com/xtaci/smux v1.5.50
	github.com/yl2chen/cidranger v1.0.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.39.0 // indirect
	go.opentelemetry.io/otel/metric v1.39.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.1 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251202230838-ff82c1b0f217 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.4.0 // indirect
)

// Vendored to make the user set swappable on a running service, so adding a
// user does not require tearing the inbound down. Upstream sing-anytls has
// UpdateUsers but assigns the map unsynchronised (a hard concurrent-map crash
// against the auth lookup); upstream sing-shadowtls has no setter at all. //H
