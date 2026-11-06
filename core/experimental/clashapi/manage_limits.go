package clashapi

import (
	"io"
	"net/http"

	"github.com/sagernet/sing/common/json"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/go-chi/render"
)

// @Summary List per-user bandwidth caps
// @Tags Limits
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]option.UserLimitOptions
// @Router /manage/limits [get]
func listLimits(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read back from the registry rather than the file: this is the state
		// actually in force, and the two only differ if the file was edited
		// by hand since start-up.
		render.JSON(w, r, s.userLimits.All())
	}
}

// @Summary Set a user's bandwidth cap
// @Tags Limits
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param name path string true "User name"
// @Param limit body option.UserLimitOptions true "Caps in Mbit/s, 0 for unlimited"
// @Success 200 {object} map[string]any
// @Failure 400 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/limits/{name} [put]
func setLimit(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var limit option.UserLimitOptions
		err = json.Unmarshal(body, &limit)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if limit.DownloadMbps < 0 || limit.UploadMbps < 0 {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("a cap cannot be negative"))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			clashOptions := ensureClashAPIOptions(&options)
			if clashOptions.UserLimits == nil {
				clashOptions.UserLimits = make(map[string]option.UserLimitOptions)
			}
			if limit.DownloadMbps == 0 && limit.UploadMbps == 0 {
				delete(clashOptions.UserLimits, name)
			} else {
				clashOptions.UserLimits[name] = limit
			}
			return options, nil
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		// A user who had no cap until now has connections that were never
		// wrapped — WrapConn hands an uncapped user its connection untouched —
		// and no amount of registry bookkeeping reaches those. Closing them
		// makes the client reconnect through the limiter. Going the other way,
		// changing a cap that already exists, is live: the buckets are retuned
		// in place, so established connections are left alone.
		wasUncapped := s.userLimits.lookup(name) == nil
		s.userLimits.Set(name, limit)
		var closed int
		if wasUncapped {
			closed = s.closeUserConnections(name)
		}
		render.JSON(w, r, render.M{
			"message":             "limit set",
			"connections_dropped": closed,
		})
	}
}

// @Summary Remove a user's bandwidth cap
// @Tags Limits
// @Produce json
// @Security BearerAuth
// @Param name path string true "User name"
// @Success 204
// @Failure 500 {object} HTTPError
// @Router /manage/limits/{name} [delete]
func deleteLimit(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		err := s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			clashOptions := ensureClashAPIOptions(&options)
			delete(clashOptions.UserLimits, name)
			return options, nil
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		// No reconnect needed in this direction: the buckets go nil and every
		// wrapped connection reads that on its next write.
		s.userLimits.Delete(name)
		render.NoContent(w, r)
	}
}

func ensureClashAPIOptions(options *option.Options) *option.ClashAPIOptions {
	if options.Experimental == nil {
		options.Experimental = &option.ExperimentalOptions{}
	}
	if options.Experimental.ClashAPI == nil {
		options.Experimental.ClashAPI = &option.ClashAPIOptions{}
	}
	return options.Experimental.ClashAPI
}

// closeUserConnections closes every tracked connection belonging to one user
// and reports how many it closed.
func (s *Server) closeUserConnections(user string) int {
	var closed int
	for _, metadata := range s.trafficManager.Connections() {
		if metadata.Metadata.User != user {
			continue
		}
		tracker := s.trafficManager.Connection(metadata.ID)
		if tracker == nil {
			continue
		}
		tracker.Close()
		closed++
	}
	return closed
}
