package box

import (
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/go-chi/chi/v5"
)

func startDebugHTTPServer(options option.DebugOptions) (*http.Server, error) {
	if options.Listen == "" {
		return nil, nil
	}
	r := chi.NewMux()
	r.Route("/debug", func(r chi.Router) {
		r.Get("/gc", func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
			go debug.FreeOSMemory()
		})
		r.Get("/memory", func(writer http.ResponseWriter, request *http.Request) {
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)

			var memObject badjson.JSONObject
			memObject.Put("heap", byteformats.FormatMemoryBytes(memStats.HeapInuse))
			memObject.Put("stack", byteformats.FormatMemoryBytes(memStats.StackInuse))
			memObject.Put("idle", byteformats.FormatMemoryBytes(memStats.HeapIdle-memStats.HeapReleased))
			memObject.Put("goroutines", runtime.NumGoroutine())
			memObject.Put("rss", rusageMaxRSS())

			encoder := json.NewEncoder(writer)
			encoder.SetIndent("", "  ")
			encoder.Encode(&memObject)
		})
		r.Route("/pprof", func(r chi.Router) {
			r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
				if !strings.HasSuffix(request.URL.Path, "/") {
					http.Redirect(writer, request, request.URL.Path+"/", http.StatusMovedPermanently)
				} else {
					pprof.Index(writer, request)
				}
			})
			// The goroutineleak profile marks what it reports as leaked for good (Go's _Gleaked), and
			// the gVisor stack of the awg endpoint always looks leaked to it: its processors park in a
			// sleeper whose waker the GC cannot see. The next packet that wakes one is a fatal "bad
			// g->status in ready", which took the core down within minutes of the first query. So the
			// profile answers only to ?force=1, for a core without a gVisor stack. //H
			r.Get("/goroutineleak", func(writer http.ResponseWriter, request *http.Request) { //H
				if request.URL.Query().Get("force") != "1" { //H
					http.Error(writer, "refused: this profile marks gVisor's parked goroutines as leaked and the next wake-up crashes the process; add ?force=1 only on a core without a gVisor stack", http.StatusConflict)
					return
				} //H
				pprof.Index(writer, request) //H
			}) //H
			r.HandleFunc("/*", pprof.Index)
			r.HandleFunc("/cmdline", pprof.Cmdline)
			r.HandleFunc("/profile", pprof.Profile)
			r.HandleFunc("/symbol", pprof.Symbol)
			r.HandleFunc("/trace", pprof.Trace)
		})
	})
	server := &http.Server{
		Addr:    options.Listen,
		Handler: r,
	}
	listener, err := net.Listen(M.NetworkFromNetAddr(N.NetworkTCP, M.ParseSocksaddr(options.Listen).Addr), options.Listen)
	if err != nil {
		return nil, E.Cause(err, "listen debug HTTP server")
	}
	go func() {
		err := server.Serve(listener)
		if err != nil && !E.IsClosed(err) {
			log.Error(E.Cause(err, "serve debug HTTP server"))
		}
	}()
	return server, nil
}
