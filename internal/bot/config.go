// Package bot is the provisioning bot: Telegram front end, user provisioning
// against a running core, client config generation and the subscription server.
//
// It replaces bot.py, whose host-specific values were spread across thirty
// environment variables and twenty source constants -- a hostname, an SNI, a
// subscription domain with a port, an admin ID, every button caption. None of
// that moved to another server without editing the source.
package bot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"time"
)

// Config is everything that is specific to one deployment.
//
// The protocol set is deliberately NOT here: it comes from the running core's
// inbounds, as it does today. A declarative list would be a second source of
// truth for something the core already states, and the two would drift.
//
// The Telegram token is not here either. Secrets in this repository live apart
// from configuration (see secrets/secrets.json), and a config file that is
// safe to read is worth more than one field saved.
type Config struct {
	Core         Core         `json:"core"`
	Tags         Tags         `json:"tags"`
	NodeTags     ChainLabels  `json:"node_tags"`
	Paths        Paths        `json:"paths"`
	Public       Public       `json:"public"`
	Subscription Subscription `json:"subscription"`
	WARP         WARP         `json:"warp"`
	MASQUEWG     MASQUEWG     `json:"masque_wg"`
	WDTT         WDTT         `json:"wdtt"`
	Bundle       Bundle       `json:"bundle"`
	Intervals    Intervals    `json:"intervals"`
	Admins       []int64      `json:"admins,omitempty"`
	// TelegramAPIURL is another Bot API server; empty is Telegram's own.
	TelegramAPIURL string `json:"telegram_api_url,omitempty"`
	// Web lets admins ask for a one-time login link to the web UI.
	Web Web `json:"web,omitempty"`
	UI  UI  `json:"ui"`
}

// Core is how to reach the running sing-box. Only the config path is given:
// the clash API's address and secret are read out of it, so they cannot
// disagree with what the core is actually listening on.
type Core struct {
	ConfigPath string `json:"config_path"`
	// ManagementPath, when set, holds only the management endpoint and secret
	// and is used instead of reading ConfigPath, which a bot running as an
	// unprivileged user cannot and should not read.
	ManagementPath string `json:"management_path,omitempty"`
	// Container is used for log lines and for naming the reload target. The
	// bot has no Docker socket by design and never addresses it directly.
	Container string `json:"container"`
}

// Paths is the bot's own state and the helpers it shells out to.
type Paths struct {
	// DataDir holds the token registry, the subscription cache, per-user
	// peers, passwords and the reload markers.
	DataDir string `json:"data_dir"`
	// WDTTConfigDir is shared with the relay shim, which watches
	// passwords.json inside it.
	WDTTConfigDir string `json:"wdtt_config_dir"`
	APK           string `json:"apk,omitempty"`
	APKURL        string `json:"apk_url,omitempty"`
	APKVersion    string `json:"apk_version,omitempty"`
	// WARPBinary registers Cloudflare accounts; CheckHashBinary validates the
	// VK call hash pool. Both are cores built elsewhere, not this binary.
	WARPBinary      string `json:"warp_binary"`
	CheckHashBinary string `json:"checkhash_binary"`
	// ControlSocket is the local control daemon's socket. Empty hides the
	// server menu: without it the bot can administer users, not the server.
	ControlSocket string `json:"control_socket,omitempty"`
}

// Web is the web UI the bot hands admins login links to. Both fields or none.
type Web struct {
	URL     string `json:"url,omitempty"`
	KeyPath string `json:"key_path,omitempty"`
}

// ReloadMarker is the file the bot touches to ask for a core reload. Something
// privileged watches it; the bot deliberately cannot restart anything itself.
func (p Paths) ReloadMarker() string { return p.DataDir + "/.reload-singbox" }

// WDTTReloadMarker is the same arrangement for the relay shim.
func (p Paths) WDTTReloadMarker() string { return p.DataDir + "/.reload-wdtt" }

// NotifyMarker is touched by host units to make the bot refresh subscriptions
// at once instead of waiting out the interval.
func (p Paths) NotifyMarker() string { return p.DataDir + "/.notify-subs" }

// VKReloginDir is shared with the host-side VK relogin helper: when the
// one-year call access token dies, that helper drives a fresh sign-in and waits
// for the verification code, which the admin types into the bot. The bot writes
// the code here and reads the helper's status from here; both sides see the same
// directory because it lives under the mounted data dir.
func (p Paths) VKReloginDir() string { return p.DataDir + "/vk-relogin" }

// VKReloginStatus is where the helper reports its state (awaiting-code when it
// wants the code); VKReloginCode is where the bot drops the six digits for it.
func (p Paths) VKReloginStatus() string { return p.VKReloginDir() + "/status" }
func (p Paths) VKReloginCode() string   { return p.VKReloginDir() + "/code" }

// ChainLabels name the multi-leg methods.
//
// They are node tags, which makes them load-bearing rather than cosmetic: a
// client keys its saved selection by tag, so renaming one is a new node
// appearing and the old one vanishing, taking the user's choice with it.
type ChainLabels struct {
	ShadowTLS string `json:"shadowtls"`
	WARP      string `json:"warp"`
	MASQUEWG  string `json:"masque_wg"`
	WDTT      string `json:"wdtt"`
	AWG       string `json:"awg"`
	AWG3      string `json:"awg3"`
}

// Tags names the inbounds and endpoints the bot addresses by name.
//
// bot.py held these as constants, which is why it could only ever run against
// one deployment: a second host with its tags spelled differently needed the
// source edited. Everything here is matched against what the live core reports,
// so a tag that does not exist shows up as that method being absent rather than
// as a crash.
type Tags struct {
	// AWG and AWG3 are the AmneziaWG endpoints handed out as profiles.
	AWG  string `json:"awg"`
	AWG3 string `json:"awg3"`
	// MASQUEWG is an internal plain-WireGuard endpoint the MASQUE listener
	// forwards into. Never offered as a profile of its own: nothing outside
	// reaches its port.
	MASQUEWG string `json:"masque_wg"`
	// ShadowTLS fronts a shadowsocks inbound, named by its detour.
	ShadowTLS string `json:"shadowtls"`
}

// MASQUEWG is WireGuard carried inside a MASQUE tunnel.
type MASQUEWG struct {
	// Port and Path are where the client connects; the endpoint behind it is
	// reached only from this host.
	Port uint16 `json:"port"`
	Path string `json:"path"`
}

// Public is what clients are told to dial. The core binds wildcards, so this
// cannot be derived from its config.
type Public struct {
	Host string `json:"host"`
	// IPv4Host is an A-only name for the UDP endpoints.
	//
	// Not a nicety: a dual-stack name resolves to AAAA first, and both the VK
	// TURN relay and the WireGuard endpoints are reachable over IPv4 only, so a
	// client handed the dual-stack name tries the v6 address and the handshake
	// never completes. Empty means "use Host", which is right for a deployment
	// with no v6 at all.
	IPv4Host string `json:"ipv4_host"`
	// DNS is what a WireGuard profile tells the client to resolve through.
	// Theirs, not ours: the tunnel carries no resolver of its own, and an
	// empty value leaves a profile that connects and resolves nothing.
	DNS string `json:"dns"`
	// CDN fronted inbounds reach a CDN edge rather than the host, keyed by
	// inbound tag.
	CDN map[string]CDNFront `json:"cdn,omitempty"`
}

// CDNFront is the edge a CDN-fronted inbound is reached through.
type CDNFront struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	SNI  string `json:"sni"`
}

// Subscription is the in-process HTTP server and the URLs handed out for it.
type Subscription struct {
	Port uint16 `json:"port"`
	// HostCF goes through a tunnel; HostDirect is reached directly and carries
	// a port because a DS-Lite line has no inbound :443 to offer.
	HostCF     string `json:"host_cf"`
	HostDirect string `json:"host_direct"`
}

// WARP is the Cloudflare-MASQUE entry leg.
type WARP struct {
	// SNI is what DPI sees. A whitelisted domain is the point of it.
	SNI  string `json:"sni"`
	Port uint16 `json:"port"`
	// InnerTag is the inbound the chain exits through, so the user keeps our
	// egress address rather than Cloudflare's.
	InnerTag string `json:"inner_tag"`
}

// WDTT is WireGuard carried inside VK call relays.
type WDTT struct {
	// ServerHost must resolve to IPv4 only: VK's TURN is v4-only, and a
	// dual-stack name resolves to AAAA first and fails.
	ServerHost string `json:"server_host"`
	DTLSPort   uint16 `json:"dtls_port"`
	Obfs       string `json:"obfs"`
	MTU        uint32 `json:"mtu"`
	// WorkersPerHash and MaxWorkers drive the auto-scaling; Workers pins a
	// fixed count when non-zero.
	WorkersPerHash int    `json:"workers_per_hash"`
	MaxWorkers     int    `json:"max_workers"`
	Workers        int    `json:"workers"`
	Container      string `json:"container"`
	// Hashes is a fallback pool for when the live pool is empty.
	Hashes []string `json:"hashes,omitempty"`
	// Tag is the core endpoint plain WireGuard arrives on once the relay has
	// stripped the obfuscation.
	Tag string `json:"tag"`
}

// Bundle controls the all-methods subscription.
type Bundle struct {
	// EnableChains adds the ShadowTLS and WARP chain nodes. Clients on a core
	// older than 2026-08-15 cannot parse them.
	EnableChains bool `json:"enable_chains"`
	EnableAWG3   bool `json:"enable_awg3"`
	// SkipTags are inbounds delivered as config files, which have no place in
	// a node list.
	SkipTags []string `json:"skip_tags,omitempty"`
	// AutoExcludeTags stay out of the urltest group: an entry leg that exists
	// to escape a blockade should not be picked for being fast.
	AutoExcludeTags []string `json:"auto_exclude_tags,omitempty"`
}

// Intervals are the background loops' periods.
type Intervals struct {
	SubRefresh  Duration `json:"sub_refresh"`
	HashCheck   Duration `json:"hash_check"`
	NotifyPoll  Duration `json:"notify_poll"`
	CoreTimeout Duration `json:"core_timeout"`
}

// UI is every string a user sees. Here so the bot can be rebranded for another
// server without touching the source.
//
// The maps are merged over the defaults rather than replacing them, so adding a
// protocol to the core does not require editing someone else's config file to
// keep the rest labelled.
type UI struct {
	Hello string `json:"hello,omitempty"`
	// AccessGranted and AccessRefused are the verdicts a user receives.
	AccessGranted string `json:"access_granted,omitempty"`
	AccessRefused string `json:"access_refused,omitempty"`
	// Messages are the texts with arguments in them, keyed by purpose. Kept
	// apart from Buttons because a format string with the wrong number of
	// placeholders is a different kind of mistake from a wrong caption.
	Messages   map[string]string `json:"messages,omitempty"`
	Buttons    map[string]string `json:"buttons,omitempty"`
	TagLabel   map[string]string `json:"tag_label,omitempty"`
	ProtoLabel map[string]string `json:"proto_label,omitempty"`
	ProtoDesc  map[string]string `json:"proto_desc,omitempty"`
	ClientHint map[string]string `json:"client_hint,omitempty"`
	// ClientApps lists the applications that can read each method, per
	// platform, keyed by tag with a "default" entry. Separate from ClientHint,
	// which names the one application a user is pointed at while generating:
	// this is the longer answer to "what do I install".
	ClientApps map[string]string `json:"client_apps,omitempty"`
	// Description and ShortDescription are what Telegram shows on the bot's
	// profile and in an empty chat; published at startup. Limits are the
	// API's: 512 and 120 characters.
	Description      string `json:"description,omitempty"`
	ShortDescription string `json:"short_description,omitempty"`
	// Commands describes each slash command for the "/" menu and the help
	// page, keyed by command name without the slash. A command with no entry
	// is not published.
	Commands map[string]string `json:"commands,omitempty"`
	// Help is the text of the rich /help page, keyed by section.
	Help map[string]string `json:"help,omitempty"`
}

// Duration is a time.Duration that reads as "60s" in JSON rather than as a
// count of nanoseconds.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bot: bad duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Build returns the duration for use.
func (d Duration) Build() time.Duration { return time.Duration(d) }

// Defaults is exactly what bot.py does today, so this host behaves identically
// with no config file at all. Every value here was its default or its constant.
func Defaults() Config {
	return Config{
		Core: Core{
			ConfigPath: "/sing-box/config.json",
			Container:  "sing-box",
		},
		Paths: Paths{
			DataDir:         "/data",
			WDTTConfigDir:   "/wdtt-cfg",
			APK:             "/apk/latest.apk",
			WARPBinary:      "/app/singbox-fork",
			CheckHashBinary: "/app/wdtt-checkhash",
		},
		Tags: Tags{
			AWG: "awg-in", AWG3: "awg3-in",
			MASQUEWG: "wg-masque-in", ShadowTLS: "shadowtls-in",
		},
		// 10876 and not 443: the MASQUE listener is on a high port because a
		// DS-Lite line has no inbound :443 to be had.
		MASQUEWG: MASQUEWG{Port: 10876, Path: "/m"},
		NodeTags: ChainLabels{
			ShadowTLS: "ShadowTLS", WARP: "WARP → сервер", MASQUEWG: "MASQUE-WG",
			WDTT: "WG-over-VK", AWG: "AmneziaWG", AWG3: "AmneziaWG 3.1",
		},
		// No hosts: they name a deployment, and a bot that guessed one would
		// hand clients somebody else's server. Validate asks for public.host.
		Public: Public{
			DNS: "1.1.1.1",
		},
		Subscription: Subscription{
			Port: 10873,
		},
		WARP: WARP{
			SNI:      "mail.ru",
			Port:     443,
			InnerTag: "vless-reality-in",
		},
		WDTT: WDTT{
			// Empty: the A-only host above is used, and ServerHost only
			// overrides it for a deployment where the relay is elsewhere.
			ServerHost: "",
			// 10867, which is the port the router actually forwards. It moved
			// from 10865 and the compose default was never corrected, so the
			// value that matters lives in the environment -- taken here from
			// the running container rather than from bot.py's source.
			DTLSPort:       10867,
			Obfs:           "rtpopus3",
			MTU:            1000,
			WorkersPerHash: 9,
			MaxWorkers:     108,
			Workers:        0,
			Container:      "wdtt-relay",
			Tag:            "wg-wdtt-in",
		},
		Bundle: Bundle{
			SkipTags:        []string{"shadowtls-in", "naive-in", "mtproto-in"},
			AutoExcludeTags: []string{"WARP → сервер"},
		},
		Intervals: Intervals{
			SubRefresh:  Duration(60 * time.Second),
			HashCheck:   Duration(time.Hour),
			NotifyPoll:  Duration(15 * time.Second),
			CoreTimeout: Duration(10 * time.Second),
		},
		UI: defaultUI(),
	}
}

func defaultUI() UI {
	return UI{
		Buttons: map[string]string{
			"getcfg":          "🔑 Мой конфиг",
			"allsub":          "🔗 Все методы (авто-обновление)",
			"mystats":         "📊 Мой трафик",
			"apk":             "📱 Android клиент",
			"a:list":          "👥 Все юзеры",
			"a:stats":         "📈 Общий трафик",
			"menu":            "⬅️ Меню",
			"back":            "⬅️ Назад",
			"warp":            "WARP → сервер (обход белых списков)",
			"wdtt":            "WG-over-VK (обход БС, все операторы)",
			"approve":         "✅ Одобрить",
			"deny":            "🚫 Отклонить",
			"a:wl":            "🔐 Доступ",
			"a:srv":           "🛠 Сервер",
			"a:gens":          "🗂 Поколения",
			"a:rb":            "⏪ Откатить",
			"srv_apply":       "✅ Применить",
			"srv_cancel":      "✖️ Отмена",
			"open_menu":       "🛡 Открыть меню",
			"copy":            "📋 Скопировать ссылку",
			"copy_cf":         "📋 Основная",
			"copy_direct":     "📋 Резервная",
			"col_command":     "Команда",
			"col_action":      "Что делает",
			"apk_unavailable": "📱 Android клиент (временно недоступен)",
			"usage_rotate":    "Использование: /rotate <uid> [uid…] — перевыпустить все креды пользователей",
			"usage_port":      "Использование: /port <протокол> <порт>, например /port awg-in 10870",
			"usage_image":     "Использование: /image <тот же репозиторий>:<тег>",
			// Leaf screens and verdicts. Every one of these was a literal in
			// bot.py, which is why the deployment could not be re-branded.
			"generate":            "🔳 Сгенерировать",
			"choose_protocol":     "Выбери протокол:",
			"unavailable":         "⛔ Недоступно.",
			"access_title":        "🔐 *Доступ*",
			"access_approved":     "одобрен",
			"access_rejected":     "отклонён",
			"access_revoked":      "удалён",
			"default_client":      "Hiddify",
			"users_title":         "👥 *Все юзеры* (трафик суммарный по всем протоколам):",
			"no_users":            "нет юзеров",
			"stats_title":         "📈 *Общий трафик*",
			"vk_pool_title":       "📞 *VK-пул*",
			"vk_not_a_link":       "не похоже на ссылку VK-звонка; нужна вида `https://vk.ru/call/join/…`",
			"vk_no_checker":       "проверка ссылок недоступна: хелпер не настроен",
			"vk_no_verdict":       "проверка не дала результата, попробуй ещё раз",
			"usage_add":           "Использование: /add <inbound> <name>",
			"usage_del":           "Использование: /del <inbound> <name>",
			"usage_reset":         "Использование: /reset <name>",
			"usage_id":            "Использование: укажи Telegram ID",
			"usage_vkhash":        "Использование: /vkhash [list|add <ссылка>|del <хеш>|check]",
			"usage_vkcode":        "Использование: /vkcode <6 цифр из звонка>",
			"vk_code_bad":         "нужен ровно 6-значный код из звонка",
			"vk_code_not_waiting": "сейчас релогин VK не ждёт кода",
			"vk_code_accepted":    "✅ код принят, завершаю вход в VK…",
			// The reason given when something changed and nothing said why.
			"change_default_reason": "изменение на сервере",
		},
		Hello: "🛡 *VPN*\n\nНажми «Мой конфиг», выбери протокол — бот выдаст персональную " +
			"ссылку (конфиг привязан к твоему Telegram‑аккаунту).",
		ShortDescription: "Персональный VPN: конфиги, подписка со всеми методами, обход блокировок.",
		Description: "Выдаёт персональные VPN-конфиги (VLESS Reality, Hysteria2, AmneziaWG и другие), " +
			"подписку со всеми методами и авто-обновлением, обходные пути для белых списков. " +
			"Доступ — по одобрению администратора: нажми /start.",
		Commands: map[string]string{
			"start":     "Начать / главное меню",
			"menu":      "Главное меню",
			"help":      "Справка: как получить конфиг",
			"whitelist": "Кто допущен и кто ждёт",
			"allow":     "Одобрить доступ: /allow <id>",
			"deny":      "Отозвать доступ: /deny <id>",
			"add":       "Добавить аккаунт: /add <inbound> <name>",
			"del":       "Удалить аккаунт: /del <inbound> <name>",
			"reset":     "Сбросить счётчики: /reset <name>",
			"rotate":    "Перевыпустить креды: /rotate <uid>…",
			"port":      "Сменить порт: /port <inbound> <порт>",
			"image":     "Сменить образ ядра: /image <repo>:<tag>",
			"pushcfg":   "Пересобрать подписки и уведомить",
			"vkhash":    "VK-пул: list | add | del | check",
			"vkcode":    "Код из VK-звонка при релогине",
			"weblogin":  "Одноразовая ссылка в веб-интерфейс",
		},
		Help: map[string]string{
			"title": "🛡 VPN — справка",
			"intro": "Бот выдаёт персональные конфиги: каждый привязан к твоему Telegram-аккаунту, " +
				"трафик считается по нему же. Ссылки и файлы никому не пересылай.",
			"steps_title": "Как подключиться",
			"steps": "Нажми «Мой конфиг» и выбери протокол — придут QR-код и ссылка или файл.\n" +
				"Отсканируй QR в клиенте на телефоне или скопируй ссылку кнопкой под сообщением.\n" +
				"Лучше взять «Все методы»: одна подписка со всеми протоколами, обновляется сама, " +
				"нода «Авто» переключается на рабочий метод при блокировке.\n" +
				"Если ничего не подключается — «WARP → сервер» или «WG-over-VK» обходят белые списки.",
			"commands_title": "Команды",
			"admin_title":    "Команды администратора",
			"admin_hint": "Кнопки в меню дублируют большинство из них; команды нужны там, где " +
				"требуется аргумент — имя аккаунта, id, порт.",
			"footer": "Статистика трафика — «Мой трафик». Вопросы по доступу — администратору сервера.",
		},
		AccessGranted: "✅ Доступ к VPN открыт! Нажми /start.",
		AccessRefused: "🚫 В доступе к VPN отказано.",
		ClientApps: map[string]string{
			"default": "📱 Android: Hiddify · v2rayNG · NekoBox\n" +
				"🍏 iPhone: Hiddify · Streisand · Shadowrocket(платн.)\n" +
				"💻 ПК: Hiddify · NekoRay · v2rayN (Win)",
			"awg-in": "📱 Android: AmneziaVPN / AmneziaWG\n" +
				"🍏 iPhone: AmneziaVPN\n💻 ПК: AmneziaVPN",
			"awg3-in": "📱 Android: AmneziaVPN / AmneziaWG\n" +
				"🍏 iPhone: AmneziaVPN\n💻 ПК: AmneziaVPN",
			"masque-wg": "📱 Android: sing‑box на ядре нашего форка (masque‑wg) — сток‑клиенты не умеют\n" +
				"🍏 iPhone: — (нет ядра с masque‑wg)\n💻 ПК: sing‑box (наш форк‑бинарь) с этим JSON",
			"snell-in": "📱 Android: Hiddify · NekoBox (импорт JSON)\n" +
				"🍏 iPhone: Surge · Stash (платн.) · Hiddify\n💻 ПК: Hiddify · sing‑box · Surge (Mac)",
			"naive-in": "📱 Android: NekoBox / husi (с naive)\n" +
				"🍏 iPhone: — (наив не поддержан; выбери другой протокол)\n" +
				"💻 ПК: naiveproxy (klzgrad) / NekoRay",
		},
		Messages: map[string]string{
			// The background loops' messages. They were missing from these
			// defaults after the port from bot.py, so every one of them went
			// out as an empty message that Telegram refused.
			"subscription_changed": "🔄 *VPN*: конфиг обновлён (%s).\n" +
				"Клиент подтянет его сам по подписке; чтобы сразу — обнови подписку в " +
				"приложении (Группы → ⟳) и переподключись.",
			"subscription_moved": "📦 *VPN переехал на новый адрес.*\n\n" +
				"Старая ссылка на подписку больше не работает, и сама она не обновится. " +
				"Замени её в приложении на новую (Группы → подписка → изменить ссылку) " +
				"или добавь заново:\n\n*Основная:*\n`%s`\n\n*Резервная:*\n`%s`\n\n" +
				"Ключи прежние — больше ничего делать не нужно.",
			"vk_pool_dead": "💀 *WG-over-VK*: мёртвые VK-хеши (исключены из выдачи):\n%s\n\n" +
				"Добавь свежие с *calls.vk.ru*: `/vkhash add <ссылка>`",
			"vk_link_died": "💀 Твой VK-звонок протух и больше не помогает обходу БС.\n" +
				"Создай новый на *calls.vk.ru* и пришли ссылку через «➕ Свой VK-звонок».",
			"vk_pool_low": "⚠️ *WG-over-VK*: живых VK-хешей осталось *%d*! " +
				"Пул почти пуст — добавь свежие с *calls.vk.ru*.",
			"access_pending": "⏳ Доступ к VPN — по одобрению администратора.\n" +
				"Твой ID: %s\nЗаявка отправлена, ожидай.",
			"access_request":    "🔔 Заявка на доступ к VPN:\n%s %s",
			"access_decided":    "🔐 *Доступ* — %s: %s",
			"pick":              "Вариант: *%s*\nКлиент: *%s*\n\nНажми «Сгенерировать» — придёт QR-код + конфиг.",
			"error":             "❌ Ошибка: %s",
			"vk_rejected":       "⚠️ Ссылка не подошла: %s",
			"my_stats":          "📊 Твой трафик:\n↑ %s  ↓ %s  (%d conn)",
			"no_stats":          "📊 Пока нет данных о трафике (конфиг не использовался).",
			"ready":             "Готово ✅\n\n%s🧩 *Рекомендуемые клиенты:*\n%s",
			"proto_desc":        "ℹ️ *Как работает:* %s\n\n",
			"apk_unavailable":   "⚠️ APK сейчас недоступен, попробуй позже.",
			"preparing_sub":     "⏳ Готовлю подписку со всеми методами… (до ~30с)",
			"generating":        "⏳ Генерирую конфиг…",
			"registering_warp":  "⏳ Регистрирую WARP и собираю конфиг… (до ~20с)",
			"provisioning_wdtt": "⏳ Провижу WG-over-VK…",
			"admin_only":        "⛔ Только для админа. Твой ID: %s",
			"web_link":          "🌐 Одноразовая ссылка для входа, действует 10 минут:\n%s",
			"web_unavailable":   "⛔ Веб-интерфейс не настроен (нет web.url и web.key_path в конфиге бота).",
			"srv_unavailable":   "⛔ Управление сервером не подключено (нет сокета control-демона).",
			"srv_failed":        "❌ %s",
			"srv_status":        "🛠 *Сервер*\n%s",
			"srv_generations":   "🗂 *Поколения*\n%s",
			"srv_plan":          "📋 *План*: %s\n%s\n\nНичего ещё не изменено. Применить?",
			"srv_applying":      "⏳ Применяю… (до нескольких минут)",
			"srv_applied":       "✅ Применено, транзакция %s",
			"srv_cancelled":     "✖️ Отменено, ничего не изменено.",
			"claim_accepted":    "✅ Готово: теперь ты администрируешь этот сервер.",
			"claim_refused":     "⛔ Код не подошёл или истёк. Новый выдаётся на сервере: `spaiter-vpn bot claim-code`.",
			"caption_awg": "🔑 *AmneziaWG* — отсканируй QR в приложении *Amnezia* / *AmneziaWG*, " +
				"либо импортируй файл ниже.",
			"caption_warp": "🔑 *WARP → сервер* — обход белых списков (чебурнет).\n" +
				"Вход через Cloudflare WARP (MASQUE h2), выход — наш сервер.\n\n" +
				"Открой этот файл в клиенте *нашего форка* (обнови до свежей версии) — " +
				"импортируется одной нодой, просто подключайся.",
			"caption_wdtt": "🔑 *WG-over-VK* — обход белых списков на *всех* операторах " +
				"(трафик как звонок ВК), выход — наш сервер.\n\n" +
				"Открой файл в клиенте *нашего форка* (свежая версия) — " +
				"ядро само поднимает VK-туннель, импортируется одной нодой.",
			"caption_json": "🔑 *%s* — импортируй файл ниже в *%s* (конфиг). " +
				"QR — для быстрого копирования.",
			"caption_link": "🔑 *%s* — отсканируй QR в *Hiddify* (или скопируй ссылку):\n\n```\n%s\n```",
			"caption_apk":  "📱 Android клиент (наш форк) %s",
			"subscription": "🔗 *Подписка: все методы* (авто-обновление)\n\n" +
				"В подписке *%d* нод — каждый протокол отдельной нодой, все с твоими " +
				"персональными ключами. Клиент сам подтянет свежий конфиг при любых изменениях " +
				"на сервере (порт/VK-хеши/ключи).\n\n" +
				"📲 *Настройка (наш форк, свежая версия):*\n" +
				"1. *Группы* → *+* → *Тип: Подписка* → вставь ссылку → сохрани.\n" +
				"2. В группе появятся все протоколы **и нода «🚀 Авто (лучший)»** — она создаётся " +
				"сама. Просто выбери её и подключайся.\n" +
				"3. Приложение само тестит все протоколы и гонит трафик через самый быстрый живой, " +
				"а если его заблокируют — автоматически переключается на обходной.\n\n" +
				"*Основная (Cloudflare):*\n`%s`\n\n*Резервная (прямая):*\n`%s`\n\n" +
				"Ссылки персональные — не передавай их другим.",
			"vk_accepted": "✅ Звонок принят и добавлен в пул — теперь он помогает обходить БС!\n" +
				"⚠️ *Не завершай этот звонок* в VK, иначе ссылка перестанет работать.\n" +
				"Если протухнет — я тебе напишу, просто пришлёшь новую.",
			"vk_already":   "↔️ Этот звонок уже в пуле и работает — спасибо!",
			"vk_try_again": "⏳ VK сейчас не отдаёт данные по этой ссылке (временно: %s). Попробуй через минуту.",
			"vk_dead": "ссылка недействительна или звонок уже закрыт (%s). " +
				"Создай новый на *calls.vk.ru* и пришли свежую.",
			"vk_removed": "🗑 Хеш `%s` убран из пула.",
			"vk_checked": "📞 Проверено %d, живых %d, новых мёртвых %d, вычищено %d.",
			"whitelist":  "🔐 *Доступ*\n\n*Разрешены:*\n%s\n*Ждут:*\n%s",
			"added":      "✅ `%s` добавлен в `%s` — конфиг ниже.",
			"added_link": "✅ `%s` добавлен в `%s`:\n\n```\n%s\n```",
			"deleted":    "🗑 `%s` удалён из `%s`.",
			"reset":      "♻️ Счётчики `%s` сброшены.",
			"pushed":     "📤 Подписки пересобраны, уведомлено %d.",
		},
		ProtoLabel: map[string]string{
			"vless": "VLESS", "hysteria2": "Hysteria2", "trojan": "Trojan",
			"vmess": "VMess", "tuic": "TUIC", "hysteria": "Hysteria",
			"shadowtls": "ShadowTLS", "naive": "NaiveProxy", "mieru": "Mieru",
			"anytls": "AnyTLS", "snell": "Snell", "mtproto": "MTProto",
		},
		TagLabel: map[string]string{
			"vless-reality-in": "VLESS Reality",
			"vless-xhttp-in":   "VLESS Reality · XHTTP",
			"hysteria-in":      "Hysteria2",
			"tuic-in":          "TUIC v5",
			"shadowtls-in":     "ShadowTLS + SS2022",
			"vless-ws-cdn-in":  "VLESS · Cloudflare CDN",
			"naive-in":         "NaiveProxy",
			"mieru-in":         "Mieru",
			"anytls-in":        "AnyTLS",
			"snell-in":         "Snell v6",
			"mtproto-in":       "Telegram-прокси (MTProto)",
			"awg-in":           "AmneziaWG",
			"awg3-in":          "AmneziaWG 3.1",
			"masque-wg":        "MASQUE + WireGuard",
		},
		ClientHint: map[string]string{
			"awg-in":   "Amnezia",
			"awg3-in":  "Amnezia 5.0.0.5+",
			"naive-in": "naiveproxy",
			// Not a VPN client: the link opens Telegram, which adds the proxy.
			"mtproto-in": "Telegram",
		},
		ProtoDesc: map[string]string{
			"vless-reality-in": "Маскируется под настоящий TLS к чужому сайту (Reality, без своего сертификата) — DPI видит обычный HTTPS. Быстрый и стойкий к блокировкам.",
			"vless-xhttp-in":   "VLESS+Reality поверх XHTTP: трафик как обычные HTTP-запросы, устойчивее к DPI, дружит с CDN.",
			"hysteria-in":      "UDP/QUIC со своим контролем перегрузки — быстрый на потерях и нестабильном канале. Минус: UDP местами режут.",
			"tuic-in":          "UDP/QUIC, низкая задержка — хорош для звонков/игр. Чувствителен к блокировке UDP.",
			"shadowtls-in":     "Shadowsocks спрятан за настоящим TLS-хендшейком к легит-домену — выглядит как обычный HTTPS.",
			"vless-ws-cdn-in":  "Подключение к edge Cloudflare (неблокируемый IP), внутри WebSocket до сервера. Хорош, когда режут по IP.",
			"naive-in":         "HTTP/2 CONNECT поверх настоящего TLS (как Chrome) — почти неотличим от обычного веба.",
			"mtproto-in":       "Прокси только для Telegram: ссылка открывает Telegram и добавляет его. Личный, трафик считается на тебя.",
			"mieru-in":         "Обфусцированный прокси без явных сигнатур: шифрует и рандомизирует трафик против DPI.",
			"anytls-in":        "Мультиплекс поверх настоящего TLS с рандомизацией размеров пакетов — маскировка под обычный HTTPS.",
			"snell-in":         "Лёгкий обфусцированный прокси (Surge) с шейпингом трафика.",
			"awg-in":           "WireGuard с обфускацией (junk-пакеты, случайные заголовки) — обходит блокировку обычного WG.",
			"awg3-in":          "AmneziaWG 3.1: поверх обфускации 2.0 шифрует заголовки пакетов (header protection), варьирует размеры, паддинг и тайминги — ответ на блокировки лета 2026. Нужен свежий клиент: Amnezia 5.0.0.5+ или AmneziaWG-android 3.0.1+; старые версии этот конфиг не поднимут.",
			"warp":             "Вход через Cloudflare WARP (MASQUE h2, неблокируемый anycast) пробивает белые списки/чебурнет, выход — наш сервер (твой IP). Для случая, когда страну отрезают от внешнего интернета.",
			"wdtt":             "WireGuard внутри TURN-звонков ВК: трафик выглядит как WebRTC-звонок, ВК разрешён на всех операторах → пробивает БС везде. Выход — наш сервер (через торрент-фильтр). Клиент — приложение qWDTT; медленнее WARP, но работает там, где WARP режут.",
		},
	}
}

// UserTypes are the inbound types that carry per-user accounts and so can be
// offered. shadowsocks is absent on purpose: it exists only as the ShadowTLS
// detour backend and is never handed out on its own.
func UserTypes() map[string]bool {
	return map[string]bool{
		"vless": true, "hysteria2": true, "trojan": true, "vmess": true,
		"tuic": true, "hysteria": true, "shadowtls": true, "naive": true,
		"mieru": true, "anytls": true, "snell": true,
		// Per-user since the core matches MTProto secrets to users; a link
		// for Telegram itself, never a node in the bundle.
		"mtproto": true,
	}
}

// JSONTags are inbounds delivered as a config file rather than a share URI.
//
// vless-xhttp-obfs-in is here because obfs mode cannot be expressed as a URI at
// all: x_padding_placement/key/header/method have no share-link equivalent and
// a client missing any of them gets 400 on every request.
func JSONTags() map[string]bool {
	return map[string]bool{
		"shadowtls-in": true, "vless-xhttp-in": true, "vless-xhttp-obfs-in": true,
		"naive-in": true, "mieru-in": true, "snell-in": true,
	}
}

// Load reads a config file over the defaults. A missing path is not an error:
// the defaults are a working configuration for the deployment this came from.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("bot: read config: %w", err)
	}

	// Decode into the defaults so an absent field keeps its default, then merge
	// the UI maps, which json would otherwise have replaced wholesale.
	base := defaultUI()
	dec := json.NewDecoder(bytes.NewReader(data))
	// Strict, like the core is about its own config: a typo in a key should
	// say so rather than silently leave the default in place.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("bot: parse %s: %w", path, err)
	}
	cfg.UI = mergeUI(base, cfg.UI)
	return cfg, cfg.Validate()
}

func mergeUI(base, over UI) UI {
	out := base
	for _, text := range []struct {
		dst *string
		src string
	}{
		{&out.Hello, over.Hello},
		{&out.AccessGranted, over.AccessGranted},
		{&out.AccessRefused, over.AccessRefused},
		{&out.Description, over.Description},
		{&out.ShortDescription, over.ShortDescription},
	} {
		if text.src != "" {
			*text.dst = text.src
		}
	}
	for _, m := range []struct{ dst, src *map[string]string }{
		{&out.Buttons, &over.Buttons},
		{&out.Messages, &over.Messages},
		{&out.TagLabel, &over.TagLabel},
		{&out.ProtoLabel, &over.ProtoLabel},
		{&out.ProtoDesc, &over.ProtoDesc},
		{&out.ClientHint, &over.ClientHint},
		{&out.ClientApps, &over.ClientApps},
		{&out.Commands, &over.Commands},
		{&out.Help, &over.Help},
	} {
		if len(*m.src) == 0 {
			continue
		}
		merged := make(map[string]string, len(*m.dst)+len(*m.src))
		maps.Copy(merged, *m.dst)
		maps.Copy(merged, *m.src)
		*m.dst = merged
	}
	return out
}

// Validate rejects the configurations that would fail later, in a place where
// the cause is no longer obvious.
func (c Config) Validate() error {
	if c.Core.ConfigPath == "" {
		return fmt.Errorf("bot: core.config_path is required")
	}
	if c.Paths.DataDir == "" {
		return fmt.Errorf("bot: paths.data_dir is required")
	}
	if c.Public.Host == "" {
		return fmt.Errorf("bot: public.host is required: clients have to be told what to dial")
	}
	if c.Subscription.Port == 0 {
		return fmt.Errorf("bot: subscription.port is required")
	}
	if c.Intervals.SubRefresh.Build() <= 0 {
		return fmt.Errorf("bot: intervals.sub_refresh must be positive")
	}
	if c.Intervals.HashCheck.Build() <= 0 {
		return fmt.Errorf("bot: intervals.hash_check must be positive")
	}
	if c.Intervals.NotifyPoll.Build() <= 0 {
		return fmt.Errorf("bot: intervals.notify_poll must be positive")
	}
	if c.WDTT.MaxWorkers > 0 && c.WDTT.WorkersPerHash > c.WDTT.MaxWorkers {
		return fmt.Errorf("bot: wdtt.workers_per_hash %d exceeds max_workers %d",
			c.WDTT.WorkersPerHash, c.WDTT.MaxWorkers)
	}
	for tag, front := range c.Public.CDN {
		if front.Host == "" || front.Port == 0 {
			return fmt.Errorf("bot: public.cdn[%s] needs a host and a port", tag)
		}
	}
	return nil
}

// Marshal renders the config as it would be written to disk.
func (c Config) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
