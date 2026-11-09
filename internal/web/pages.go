package web

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
)

type statusView struct {
	Tier          string `json:"tier"`
	Image         string `json:"image"`
	SeedUsers     int    `json:"seedUsers"`
	Bot           bool   `json:"bot"`
	Generation    uint64 `json:"generation"`
	Transaction   string `json:"transaction"`
	ServicesError string `json:"servicesError"`
	Services      []struct {
		Service string `json:"Service"`
		State   string `json:"State"`
		Health  string `json:"Health"`
	} `json:"services"`
}

type generationView struct {
	Sequence    uint64 `json:"Sequence"`
	Transaction string `json:"Transaction"`
	CommittedAt string `json:"CommittedAt"`
}

type homeData struct {
	CSRF        string
	Error       string
	Status      statusView
	Generations []generationView
}

type planView struct {
	Mode    string `json:"mode"`
	Changes []struct {
		Path   string `json:"path"`
		Before any    `json:"before"`
		After  any    `json:"after"`
	} `json:"changes"`
	Actions []struct {
		ID          string `json:"id"`
		Disposition string `json:"disposition"`
		Mutates     bool   `json:"mutates"`
		Summary     string `json:"summary"`
		Reason      string `json:"reason"`
	} `json:"actions"`
}

type planData struct {
	CSRF    string
	Summary string
	Ticket  string
	Plan    planView
}

func parsePlan(raw json.RawMessage) planView {
	var view planView
	_ = json.Unmarshal(raw, &view)
	return view
}

type page struct {
	name string
	data any
}

func pageMessage(title, text string) page {
	return page{"message", map[string]string{"Title": title, "Text": text}}
}
func pageResult(title, text, output string) page {
	return page{"result", map[string]string{"Title": title, "Text": text, "Output": output}}
}
func pageHome(data homeData) page { return page{"home", data} }
func pagePlan(data planData) page { return page{"plan", data} }

var funcs = template.FuncMap{
	"json": func(v any) string {
		data, _ := json.Marshal(v)
		return string(data)
	},
}

var templates = template.Must(template.New("").Funcs(funcs).Parse(`
{{define "head"}}<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>spaiter-vpn</title>
<style>
:root{--bg:#f6f7f9;--fg:#1d2329;--card:#fff;--line:#d9dee5;--muted:#5f6b78;--accent:#2457c5;--warn:#a5321f}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e4e8ec;--card:#1c2126;--line:#2e353d;--muted:#98a3ae;--accent:#7aa2ff;--warn:#ff8a73}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:880px;margin:0 auto;padding:16px}h1{font-size:20px}h2{font-size:16px;margin:0 0 8px}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:12px 0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}
code,pre{font:13px ui-monospace,monospace}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);padding:8px;border-radius:6px;max-height:420px;overflow:auto}
form.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:6px 0}input{padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);min-width:0}
button{padding:6px 12px;border:1px solid var(--accent);border-radius:6px;background:var(--accent);color:#fff;cursor:pointer}button.plain{background:transparent;color:var(--accent)}
.muted{color:var(--muted)}.warn{color:var(--warn)}
</style></head><body><main>{{end}}
{{define "foot"}}</main></body></html>{{end}}

{{define "message"}}{{template "head"}}<h1>{{.Title}}</h1><section><p>{{.Text}}</p><p><a href="/">На главную</a></p></section>{{template "foot"}}{{end}}

{{define "result"}}{{template "head"}}<h1>{{.Title}}</h1><section><p>{{.Text}}</p>{{if .Output}}<pre>{{.Output}}</pre>{{end}}<p><a href="/">На главную</a></p></section>{{template "foot"}}{{end}}

{{define "home"}}{{template "head"}}
<h1>spaiter-vpn</h1>
{{if .Error}}<section class="warn">Демон управления не ответил: {{.Error}}</section>{{end}}
<section><h2>Состояние</h2>
<table><tr><th>Поколение</th><td>{{.Status.Generation}} <span class="muted">{{.Status.Transaction}}</span></td></tr>
<tr><th>Уровень</th><td>{{.Status.Tier}}, seed-пользователей: {{.Status.SeedUsers}}, бот: {{if .Status.Bot}}да{{else}}нет{{end}}</td></tr>
<tr><th>Образ</th><td><code>{{.Status.Image}}</code></td></tr></table>
{{if .Status.Services}}<table>{{range .Status.Services}}<tr><td>{{.Service}}</td><td>{{.State}}</td><td class="muted">{{.Health}}</td></tr>{{end}}</table>{{end}}
{{if .Status.ServicesError}}<p class="warn">{{.Status.ServicesError}}</p>{{end}}
</section>
<section><h2>Изменить</h2><p class="muted">Каждое изменение сначала показывает план; на сервере ничего не меняется до «Применить».</p>
<form class="row" method="post" action="/prepare"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="settings">
<label>Порт <input name="protocol" placeholder="awg-in" size="12"></label><input name="port" placeholder="10870" size="7" inputmode="numeric"><button>План</button></form>
<form class="row" method="post" action="/prepare"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="settings">
<label>Включить <input name="enable" placeholder="tuic-in" size="12"></label><label>Выключить <input name="disable" placeholder="mieru-in" size="12"></label><button>План</button></form>
<form class="row" method="post" action="/prepare"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="image">
<label>Образ <input name="image" placeholder="тот же репозиторий:тег" size="40"></label><button>План</button></form>
<form class="row" method="post" action="/prepare"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="rotate">
<label>Перевыпустить креды <input name="users" placeholder="alice, 42" size="24"></label><button>План</button></form>
<form class="row" method="post" action="/prepare"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="kind" value="rollback">
<label>Откатить к поколению <input name="generation" placeholder="предыдущему" size="10" inputmode="numeric"></label><button>План</button></form>
</section>
<section><h2>Поколения</h2>{{if .Generations}}<table>{{range .Generations}}<tr><td>{{.Sequence}}</td><td class="muted">{{.CommittedAt}}</td><td><code>{{.Transaction}}</code></td></tr>{{end}}</table>{{else}}<p class="muted">нет данных</p>{{end}}</section>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="plain">Выйти</button></form>
{{template "foot"}}{{end}}

{{define "plan"}}{{template "head"}}
<h1>План: {{.Summary}}</h1>
<section><p>Режим: <b>{{.Plan.Mode}}</b>. Ничего ещё не изменено.</p>
{{if .Plan.Changes}}<h2>Изменения желаемого состояния</h2><table>{{range .Plan.Changes}}<tr><td><code>{{.Path}}</code></td><td>{{json .Before}} → {{json .After}}</td></tr>{{end}}</table>{{end}}
<h2>Что изменится на хосте</h2><table>{{range .Plan.Actions}}{{if .Mutates}}<tr><td><code>{{.ID}}</code></td><td>{{.Summary}}<div class="muted">{{.Reason}}</div></td></tr>{{end}}{{end}}</table>
<form class="row" method="post" action="/commit"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="ticket" value="{{.Ticket}}"><button>Применить</button></form>
<form class="row" method="post" action="/cancel"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="ticket" value="{{.Ticket}}"><button class="plain">Отмена</button></form>
</section>{{template "foot"}}{{end}}
`))

func render(w http.ResponseWriter, status int, p page) {
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, p.name, p.data); err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
