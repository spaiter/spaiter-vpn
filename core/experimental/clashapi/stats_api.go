package clashapi

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func statsRouter(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Get("/users", getAllUserStats(s))
	r.Get("/users/{name}", getUserStats(s))
	r.Delete("/users/{name}", resetUserStats(s))
	r.Get("/users/{name}/resources", getUserResources(s))
	r.Get("/inbounds", getInboundStats(s)) //H
	return r
}

// getInboundStats answers per inbound and day, summed over users: which
// transports carry sustained streams and which only requests. //H
func getInboundStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		days := 7
		if d := r.URL.Query().Get("days"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
				days = parsed
			}
		}
		stats, err := s.userStatsManager.GetInboundDaily(days)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if stats == nil {
			stats = []InboundDailyStats{}
		}
		render.JSON(w, r, stats)
	}
}

func getAllUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := s.userStatsManager.GetAllStats()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if stats == nil {
			stats = []UserStatsSummary{}
		}
		render.JSON(w, r, stats)
	}
}

func getUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
				days = parsed
			}
		}
		daily, err := s.userStatsManager.GetUserDaily(name, days)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if daily == nil {
			daily = []UserDailyStats{}
		}
		render.JSON(w, r, render.M{
			"user":  name,
			"daily": daily,
		})
	}
}

func resetUserStats(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		err := s.userStatsManager.ResetUser(name)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	}
}

func getUserResources(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
				days = parsed
			}
		}
		resources, err := s.userStatsManager.GetUserResources(name, days)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if resources == nil {
			resources = []UserResourceStats{}
		}
		render.JSON(w, r, resources)
	}
}
