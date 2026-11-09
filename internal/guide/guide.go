// Package guide renders one user's connection guide: every method the bot
// offers, each with its link or file, a QR code and what to open it in, plus
// the all-methods subscription. One self-contained HTML file, readable
// offline and printable to PDF.
//
// It replaces the Python scripts that used to live in guide/. Those
// re-implemented the bot's provisioning and link formats by hand and drifted;
// this goes through the bot's own service, so a guide hands out exactly what
// the bot would.
package guide

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"sort"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	botcfg "github.com/spaiter/spaiter-vpn/internal/bot"
	"github.com/spaiter/spaiter-vpn/internal/bot/clientcfg"
	"github.com/spaiter/spaiter-vpn/internal/manage"
)

// Source is the bot's service, as far as a guide needs it.
type Source interface {
	Config() botcfg.Config
	UserInbounds(ctx context.Context) ([]manage.InboundRef, error)
	OfferedEndpoints(ctx context.Context) ([]clientcfg.Endpoint, error)
	Link(ctx context.Context, tag, uid string) (string, error)
	JSONConfig(ctx context.Context, tag, uid string) ([]byte, error)
	AWGConf(ctx context.Context, tag, uid string) (string, error)
	Bundle(ctx context.Context, uid string, provision bool) ([]byte, error)
}

// Subscriptions is the bot's token registry, as far as a guide needs it.
type Subscriptions interface {
	SubscriptionToken(uid string) (string, error)
	SetBundleCache(token string, bundle []byte) error
}

// Method is one way to connect.
type Method struct {
	Label       string
	Description string
	Client      string
	// Link is a share URI; File is a config to import, with its name.
	Link     string
	File     []byte
	FileName string
	QR       template.URL
	Error    string
}

// Guide is everything one page shows.
type Guide struct {
	User          string
	Generated     string
	Subscriptions []string
	SubscriptionQ template.URL
	Methods       []Method
	// Bundle is the user's subscription, for `spaiter-vpn verify`.
	Bundle []byte `json:"-"`
}

// Build provisions the user on every offered method, as pressing each button
// in the bot would, and collects what to hand them. A method that fails is
// listed with its error rather than failing the guide.
func Build(ctx context.Context, src Source, subs Subscriptions, user string, now time.Time) (Guide, error) {
	cfg := src.Config()
	guide := Guide{User: user, Generated: now.UTC().Format("2006-01-02 15:04 UTC")}

	bundle, err := src.Bundle(ctx, user, true)
	if err != nil {
		return Guide{}, fmt.Errorf("guide: build the subscription: %w", err)
	}
	guide.Bundle = bundle
	if subs != nil {
		token, err := subs.SubscriptionToken(user)
		if err != nil {
			return Guide{}, err
		}
		if err := subs.SetBundleCache(token, bundle); err != nil {
			return Guide{}, err
		}
		if host := cfg.Subscription.HostCF; host != "" {
			guide.Subscriptions = append(guide.Subscriptions, "https://"+host+"/sub/"+token)
		}
		if host := cfg.Subscription.HostDirect; host != "" {
			guide.Subscriptions = append(guide.Subscriptions, "http://"+host+"/sub/"+token)
		}
		if len(guide.Subscriptions) > 0 {
			guide.SubscriptionQ = qr(guide.Subscriptions[0])
		}
	}

	inbounds, err := src.UserInbounds(ctx)
	if err != nil {
		return Guide{}, err
	}
	sort.Slice(inbounds, func(i, j int) bool { return inbounds[i].Tag < inbounds[j].Tag })
	for _, inbound := range inbounds {
		method := describe(cfg, inbound.Tag, inbound.Type)
		if botcfg.JSONTags()[inbound.Tag] {
			config, err := src.JSONConfig(ctx, inbound.Tag, user)
			if err != nil {
				method.Error = err.Error()
			} else {
				method.File, method.FileName = config, inbound.Tag+"-"+user+".json"
			}
		} else {
			link, err := src.Link(ctx, inbound.Tag, user)
			switch {
			case err != nil:
				method.Error = err.Error()
			case link == "":
				continue
			default:
				method.Link, method.QR = link, qr(link)
			}
		}
		guide.Methods = append(guide.Methods, method)
	}
	endpoints, err := src.OfferedEndpoints(ctx)
	if err != nil {
		return Guide{}, err
	}
	for _, endpoint := range endpoints {
		method := describe(cfg, endpoint.Tag, "awg")
		conf, err := src.AWGConf(ctx, endpoint.Tag, user)
		if err != nil {
			method.Error = err.Error()
		} else {
			method.File, method.FileName, method.QR = []byte(conf), shortName(user)+".conf", qr(conf)
		}
		guide.Methods = append(guide.Methods, method)
	}
	return guide, nil
}

func describe(cfg botcfg.Config, tag, protocol string) Method {
	label := cfg.UI.TagLabel[tag]
	if label == "" {
		label = cfg.UI.ProtoLabel[protocol]
	}
	if label == "" {
		label = tag
	}
	return Method{Label: label, Description: cfg.UI.ProtoDesc[tag], Client: cfg.UI.ClientHint[tag]}
}

// shortName fits WireGuard's 15-character tunnel-name limit, which a numeric
// Telegram id may exceed.
func shortName(user string) string {
	if len(user) > 15 {
		return user[len(user)-15:]
	}
	return user
}

// qr renders text as an inline PNG. Content too long for a QR code gets none;
// the text is on the page anyway.
func qr(text string) template.URL {
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}

// Render writes the guide as one HTML page.
func Render(g Guide) ([]byte, error) {
	var buf bytes.Buffer
	if err := page.Execute(&buf, g); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var page = template.Must(template.New("guide").Funcs(template.FuncMap{
	"dataURL": func(data []byte) template.URL {
		return template.URL("data:application/octet-stream;base64," + base64.StdEncoding.EncodeToString(data))
	},
	"text": func(data []byte) string { return string(data) },
}).Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подключение — {{.User}}</title>
<style>
:root{--bg:#fff;--fg:#1d2329;--line:#d9dee5;--muted:#5f6b78;--accent:#2457c5}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e4e8ec;--line:#2e353d;--muted:#98a3ae;--accent:#7aa2ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}h1{font-size:22px}h2{font-size:17px;margin:0 0 6px}
section{border:1px solid var(--line);border-radius:8px;padding:14px;margin:14px 0;break-inside:avoid}
.grid{display:flex;flex-wrap:wrap;gap:14px;align-items:flex-start}.grid img{width:200px;height:200px;image-rendering:pixelated;background:#fff;padding:6px;border-radius:6px}
.text{flex:1;min-width:240px}code,pre{font:12px ui-monospace,monospace;word-break:break-all;white-space:pre-wrap}
.muted{color:var(--muted)}a{color:var(--accent)}
@media print{a[download]{display:none}}
</style></head><body><main>
<h1>Подключение к VPN — {{.User}}</h1>
<p class="muted">Создано {{.Generated}}. Ссылки и коды личные: не пересылайте их.</p>
{{if .Subscriptions}}<section><h2>Все методы одной подпиской (рекомендуется)</h2><div class="grid">
{{if .SubscriptionQ}}<img alt="QR подписки" src="{{.SubscriptionQ}}">{{end}}
<div class="text"><p>Добавьте ссылку как подписку в клиенте: он сам обновляет методы и выбирает лучший.</p>
{{range .Subscriptions}}<p><code>{{.}}</code></p>{{end}}</div></div></section>{{end}}
{{range .Methods}}<section><h2>{{.Label}}</h2>
{{if .Description}}<p>{{.Description}}</p>{{end}}{{if .Client}}<p class="muted">Клиент: {{.Client}}</p>{{end}}
{{if .Error}}<p class="muted">Недоступно: {{.Error}}</p>{{else}}<div class="grid">
{{if .QR}}<img alt="QR" src="{{.QR}}">{{end}}
<div class="text">{{if .Link}}<p><code>{{.Link}}</code></p>{{end}}
{{if .File}}<p><a download="{{.FileName}}" href="{{dataURL .File}}">Скачать {{.FileName}}</a></p>{{if not .QR}}<pre>{{text .File}}</pre>{{end}}{{end}}
</div></div>{{end}}</section>{{end}}
</main></body></html>`))
