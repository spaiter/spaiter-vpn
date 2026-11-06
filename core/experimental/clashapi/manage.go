package clashapi

import (
	"io"
	"net/http"

	"github.com/sagernet/sing/common/json"
	"github.com/spaiter/spaiter-vpn/core/log"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func manageRouter(s *Server, logFactory log.Factory) http.Handler {
	r := chi.NewRouter()

	// Full config (read-only)
	r.Get("/config", getFullConfig(s))

	// Push the config file into the running instance. The CRUD routes below
	// only rewrite the file; nothing takes effect until this is called. //H
	r.Post("/apply", applyConfig(s, logFactory))

	// Inbound CRUD
	r.Get("/inbounds", listInbounds(s))
	r.Post("/inbounds", addInbound(s))
	r.Get("/inbounds/{tag}", getInbound(s))
	r.Put("/inbounds/{tag}", updateInbound(s))
	r.Delete("/inbounds/{tag}", deleteInbound(s))

	// Endpoint CRUD
	r.Get("/endpoints", listEndpoints(s))
	r.Post("/endpoints", addEndpoint(s))
	r.Get("/endpoints/{tag}", getEndpoint(s))
	r.Put("/endpoints/{tag}", updateEndpoint(s))
	r.Delete("/endpoints/{tag}", deleteEndpoint(s))

	// User CRUD
	r.Get("/inbounds/{tag}/users", listUsers(s))
	r.Post("/inbounds/{tag}/users", addUser(s))
	r.Get("/inbounds/{tag}/users/{name}", getUser(s))
	r.Put("/inbounds/{tag}/users/{name}", updateUser(s))
	r.Delete("/inbounds/{tag}/users/{name}", deleteUser(s))

	// Per-user bandwidth caps. These deliberately break the convention above:
	// they rewrite the config file AND take effect in the running instance, so
	// no /apply — and therefore no dropped sessions — is needed to change a
	// cap. //H
	r.Get("/limits", listLimits(s))
	r.Put("/limits/{name}", setLimit(s))
	r.Delete("/limits/{name}", deleteLimit(s))

	return r
}

// @Summary Get full config
// @Tags Config
// @Produce json
// @Security BearerAuth
// @Success 200 {object} option.Options
// @Failure 500 {object} HTTPError
// @Router /manage/config [get]
func getFullConfig(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		data, err := json.MarshalContext(s.ctx, options)
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}

// Inbound handlers

type inboundSummary struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// @Summary List inbounds
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Success 200 {array} inboundSummary
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds [get]
func listInbounds(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		summaries := make([]inboundSummary, len(options.Inbounds))
		for i, inbound := range options.Inbounds {
			summaries[i] = inboundSummary{
				Tag:  inbound.Tag,
				Type: inbound.Type,
			}
		}
		render.JSON(w, r, summaries)
	}
}

// @Summary Get inbound by tag
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Success 200 {object} option.Inbound
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [get]
func getInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for i := range options.Inbounds {
			if options.Inbounds[i].Tag == tag {
				data, err := json.MarshalContext(s.ctx, &options.Inbounds[i])
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, newError(err.Error()))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
				return
			}
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// @Summary Add new inbound
// @Tags Inbounds
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param inbound body object true "Inbound config (must include type and tag)"
// @Success 201 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 409 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds [post]
func addInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var inbound option.Inbound
		err = inbound.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if inbound.Tag == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("inbound tag is required"))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for _, existing := range options.Inbounds {
				if existing.Tag == inbound.Tag {
					return options, &conflictError{Message: "inbound " + inbound.Tag + " already exists"}
				}
			}
			options.Inbounds = append(options.Inbounds, inbound)
			return options, nil
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, render.M{"message": "inbound added"})
	}
}

// @Summary Replace inbound
// @Tags Inbounds
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param inbound body object true "New inbound config"
// @Success 200 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [put]
func updateInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var inbound option.Inbound
		err = inbound.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, existing := range options.Inbounds {
				if existing.Tag == tag {
					inbound.Tag = tag
					options.Inbounds[i] = inbound
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.JSON(w, r, render.M{"message": "inbound updated"})
	}
}

// @Summary Remove inbound
// @Tags Inbounds
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Success 204
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag} [delete]
func deleteInbound(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		err := s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, inbound := range options.Inbounds {
				if inbound.Tag == tag {
					options.Inbounds = append(options.Inbounds[:i], options.Inbounds[i+1:]...)
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.NoContent(w, r)
	}
}

// Endpoint handlers

type endpointSummary struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
}

// @Summary List endpoints
// @Tags Endpoints
// @Produce json
// @Security BearerAuth
// @Success 200 {array} endpointSummary
// @Failure 500 {object} HTTPError
// @Router /manage/endpoints [get]
func listEndpoints(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		summaries := make([]endpointSummary, len(options.Endpoints))
		for i, endpoint := range options.Endpoints {
			summaries[i] = endpointSummary{
				Tag:  endpoint.Tag,
				Type: endpoint.Type,
			}
		}
		render.JSON(w, r, summaries)
	}
}

// @Summary Get endpoint by tag
// @Tags Endpoints
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Endpoint tag"
// @Success 200 {object} option.Endpoint
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/endpoints/{tag} [get]
func getEndpoint(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for i := range options.Endpoints {
			if options.Endpoints[i].Tag == tag {
				data, err := json.MarshalContext(s.ctx, &options.Endpoints[i])
				if err != nil {
					render.Status(r, http.StatusInternalServerError)
					render.JSON(w, r, newError(err.Error()))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(data)
				return
			}
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// @Summary Add new endpoint
// @Tags Endpoints
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param endpoint body object true "Endpoint config (must include type and tag)"
// @Success 201 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 409 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/endpoints [post]
func addEndpoint(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var endpoint option.Endpoint
		err = endpoint.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		if endpoint.Tag == "" {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("endpoint tag is required"))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for _, existing := range options.Endpoints {
				if existing.Tag == endpoint.Tag {
					return options, &conflictError{Message: "endpoint " + endpoint.Tag + " already exists"}
				}
			}
			options.Endpoints = append(options.Endpoints, endpoint)
			return options, nil
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, render.M{"message": "endpoint added"})
	}
}

// @Summary Replace endpoint
// @Tags Endpoints
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Endpoint tag"
// @Param endpoint body object true "New endpoint config"
// @Success 200 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/endpoints/{tag} [put]
func updateEndpoint(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		var endpoint option.Endpoint
		err = endpoint.UnmarshalJSONContext(s.ctx, body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, existing := range options.Endpoints {
				if existing.Tag == tag {
					endpoint.Tag = tag
					options.Endpoints[i] = endpoint
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.JSON(w, r, render.M{"message": "endpoint updated"})
	}
}

// @Summary Remove endpoint
// @Tags Endpoints
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Endpoint tag"
// @Success 204
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/endpoints/{tag} [delete]
func deleteEndpoint(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		err := s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, endpoint := range options.Endpoints {
				if endpoint.Tag == tag {
					options.Endpoints = append(options.Endpoints[:i], options.Endpoints[i+1:]...)
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.NoContent(w, r)
	}
}
