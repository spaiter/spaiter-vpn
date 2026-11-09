package clashapi

import (
	"net/http"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
	"github.com/spaiter/spaiter-vpn/core/adapter"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/go-chi/render"
)

// applyOutcome records what had to be done per tag, so the caller can see
// whether a change was absorbed without dropping connections. //H
type applyOutcome struct {
	Reloaded  []string `json:"reloaded"`  // user/peer list swapped in place
	Recreated []string `json:"recreated"` // torn down and rebuilt, sessions lost
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
}

func (o *applyOutcome) empty() bool {
	return len(o.Reloaded) == 0 && len(o.Recreated) == 0 && len(o.Added) == 0 && len(o.Removed) == 0
}

// @Summary Apply the config file to the running instance
// @Description Diffs the config file against what is live and applies it
// @Description without restarting: inbounds whose user list alone changed get
// @Description the list swapped in place, WireGuard endpoints get peers added
// @Description or removed incrementally, anything else is recreated.
// @Tags Manage
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object{message=string,inbounds=object,endpoints=object}
// @Failure 500 {object} HTTPError
// @Router /manage/apply [post]
func applyConfig(s *Server, logFactory log.Factory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		desired, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		applied, err := s.configManager.Applied()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		inbounds, err := s.applyInbounds(logFactory, applied.Inbounds, desired.Inbounds)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		endpoints, err := s.applyEndpoints(logFactory, applied.Endpoints, desired.Endpoints)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		// Only now is the file truly live. Recording it earlier would make a
		// failed apply look applied and silently skip those tags next time.
		s.configManager.SetApplied(desired)

		message := "config applied"
		if inbounds.empty() && endpoints.empty() {
			message = "no changes to apply"
		}
		render.JSON(w, r, render.M{"message": message, "inbounds": inbounds, "endpoints": endpoints})
	}
}

func (s *Server) applyInbounds(logFactory log.Factory, applied, desired []option.Inbound) (*applyOutcome, error) {
	manager := service.FromContext[adapter.InboundManager](s.ctx)
	if manager == nil {
		return nil, E.New("inbound manager not available")
	}
	router := service.FromContext[adapter.Router](s.ctx)
	outcome := new(applyOutcome)

	appliedByTag := make(map[string]option.Inbound, len(applied))
	for _, inbound := range applied {
		appliedByTag[inbound.Tag] = inbound
	}

	for _, want := range desired {
		have, exists := appliedByTag[want.Tag]
		delete(appliedByTag, want.Tag)

		create := func(entry option.Inbound) error {
			// Same logger prefix box.go gives an inbound, so log lines stay
			// indistinguishable from those of a normally started one.
			return manager.Create(s.ctx, router,
				logFactory.NewLogger(F.ToString("inbound/", entry.Type, "[", entry.Tag, "]")),
				entry.Tag, entry.Type, entry.Options)
		}
		recreate := func() error {
			existed := false
			if _, loaded := manager.Get(want.Tag); loaded {
				if err := manager.Remove(want.Tag); err != nil {
					return E.Cause(err, "remove inbound ", want.Tag)
				}
				existed = true
			}
			err := create(want)
			if err == nil {
				return nil
			}
			// The listener is already gone at this point, so leaving it at
			// that would make a rejected config worse than the one we started
			// from — the inbound would simply vanish until the next restart.
			// Put the previous definition back and report both failures.
			if existed {
				if backErr := create(have); backErr != nil {
					return E.Cause(err, "create inbound ", want.Tag,
						" (rollback also failed: ", backErr, "; inbound is DOWN)")
				}
				s.logger.Warn("inbound ", want.Tag, ": rejected, rolled back to the previous definition")
			}
			return E.Cause(err, "create inbound ", want.Tag)
		}

		if !exists {
			if err := recreate(); err != nil {
				return nil, err
			}
			outcome.Added = append(outcome.Added, want.Tag)
			continue
		}

		changed, usersOnly, err := diffOptions(s.ctx, have, want, "users")
		if err != nil {
			return nil, err
		}
		if _, live := manager.Get(want.Tag); !live {
			// In the snapshot but not running: an earlier apply failed between
			// Remove and Create. Comparing against the snapshot alone would
			// call this "unchanged" and leave the inbound down forever.
			if err := recreate(); err != nil {
				return nil, err
			}
			outcome.Recreated = append(outcome.Recreated, want.Tag)
			continue
		}
		if !changed {
			continue
		}
		if usersOnly && want.Type == have.Type {
			if current, loaded := manager.Get(want.Tag); loaded {
				if reloader, ok := current.(adapter.UserReloader); ok {
					if err := reloader.ReloadUsers(want.Options); err == nil {
						outcome.Reloaded = append(outcome.Reloaded, want.Tag)
						continue
					} else {
						s.logger.Warn("inbound ", want.Tag, ": user reload failed, recreating: ", err)
					}
				}
			}
		}
		if err := recreate(); err != nil {
			return nil, err
		}
		outcome.Recreated = append(outcome.Recreated, want.Tag)
	}

	// Whatever is left in appliedByTag is gone from the file.
	for tag := range appliedByTag {
		if _, loaded := manager.Get(tag); !loaded {
			continue
		}
		if err := manager.Remove(tag); err != nil {
			return nil, E.Cause(err, "remove inbound ", tag)
		}
		outcome.Removed = append(outcome.Removed, tag)
	}
	return outcome, nil
}

func (s *Server) applyEndpoints(logFactory log.Factory, applied, desired []option.Endpoint) (*applyOutcome, error) {
	manager := service.FromContext[adapter.EndpointManager](s.ctx)
	if manager == nil {
		return nil, E.New("endpoint manager not available")
	}
	router := service.FromContext[adapter.Router](s.ctx)
	outcome := new(applyOutcome)

	appliedByTag := make(map[string]option.Endpoint, len(applied))
	for _, endpoint := range applied {
		appliedByTag[endpoint.Tag] = endpoint
	}

	for _, want := range desired {
		have, exists := appliedByTag[want.Tag]
		delete(appliedByTag, want.Tag)

		create := func(entry option.Endpoint) error {
			// box.go tags the endpoint's context with its own outbound name;
			// without it the endpoint cannot dial through itself.
			endpointCtx := adapter.WithContext(s.ctx, &adapter.InboundContext{Outbound: entry.Tag})
			return manager.Create(endpointCtx, router,
				logFactory.NewLogger(F.ToString("endpoint/", entry.Type, "[", entry.Tag, "]")),
				entry.Tag, entry.Type, entry.Options)
		}
		recreate := func() error {
			existed := false
			if _, loaded := manager.Get(want.Tag); loaded {
				if err := manager.Remove(want.Tag); err != nil {
					return E.Cause(err, "remove endpoint ", want.Tag)
				}
				existed = true
			}
			err := create(want)
			if err == nil {
				return nil
			}
			// Same reasoning as for inbounds: a rejected config must not leave
			// the endpoint torn down. Restore the previous definition.
			if existed {
				if backErr := create(have); backErr != nil {
					return E.Cause(err, "create endpoint ", want.Tag,
						" (rollback also failed: ", backErr, "; endpoint is DOWN)")
				}
				s.logger.Warn("endpoint ", want.Tag, ": rejected, rolled back to the previous definition")
			}
			return E.Cause(err, "create endpoint ", want.Tag)
		}

		if !exists {
			if err := recreate(); err != nil {
				return nil, err
			}
			outcome.Added = append(outcome.Added, want.Tag)
			continue
		}

		changed, peersOnly, err := diffOptions(s.ctx, have, want, "peers")
		if err != nil {
			return nil, err
		}
		if _, live := manager.Get(want.Tag); !live {
			// In the snapshot but not running — see the inbound path.
			if err := recreate(); err != nil {
				return nil, err
			}
			outcome.Recreated = append(outcome.Recreated, want.Tag)
			continue
		}
		if !changed {
			continue
		}
		if peersOnly && want.Type == have.Type {
			if current, loaded := manager.Get(want.Tag); loaded {
				if reloader, ok := current.(adapter.PeerReloader); ok {
					if err := reloader.ReloadPeers(want.Options); err == nil {
						outcome.Reloaded = append(outcome.Reloaded, want.Tag)
						continue
					} else {
						s.logger.Warn("endpoint ", want.Tag, ": peer reload failed, recreating: ", err)
					}
				}
			}
		}
		if err := recreate(); err != nil {
			return nil, err
		}
		outcome.Recreated = append(outcome.Recreated, want.Tag)
	}

	for tag := range appliedByTag {
		if _, loaded := manager.Get(tag); !loaded {
			continue
		}
		if err := manager.Remove(tag); err != nil {
			return nil, E.Cause(err, "remove endpoint ", tag)
		}
		outcome.Removed = append(outcome.Removed, tag)
	}
	return outcome, nil
}
