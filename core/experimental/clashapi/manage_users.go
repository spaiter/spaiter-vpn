package clashapi

import (
	"io"
	"net/http"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json"
	C "github.com/spaiter/spaiter-vpn/core/constant"
	"github.com/spaiter/spaiter-vpn/core/option"

	"github.com/go-chi/render"
)

func getInboundUsers(inbound option.Inbound) ([]any, error) {
	switch inbound.Type {
	case C.TypeShadowsocks:
		opts, ok := inbound.Options.(*option.ShadowsocksInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeVMess:
		opts, ok := inbound.Options.(*option.VMessInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeTrojan:
		opts, ok := inbound.Options.(*option.TrojanInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeVLESS:
		opts, ok := inbound.Options.(*option.VLESSInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeHysteria2:
		opts, ok := inbound.Options.(*option.Hysteria2InboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeHysteria:
		opts, ok := inbound.Options.(*option.HysteriaInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeTUIC:
		opts, ok := inbound.Options.(*option.TUICInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeSSH:
		opts, ok := inbound.Options.(*option.SSHInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeMieru:
		opts, ok := inbound.Options.(*option.MieruInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeMTProto:
		opts, ok := inbound.Options.(*option.MTProtoInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeShadowTLS:
		opts, ok := inbound.Options.(*option.ShadowTLSInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeAnyTLS:
		opts, ok := inbound.Options.(*option.AnyTLSInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeSnell:
		opts, ok := inbound.Options.(*option.SnellInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeNaive:
		opts, ok := inbound.Options.(*option.NaiveInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeSOCKS:
		opts, ok := inbound.Options.(*option.SocksInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeHTTP:
		opts, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	case C.TypeMixed:
		opts, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		if !ok {
			return nil, nil
		}
		users := make([]any, len(opts.Users))
		for i, u := range opts.Users {
			users[i] = u
		}
		return users, nil
	default:
		return nil, newError("protocol " + inbound.Type + " does not support users")
	}
}

func unmarshalUser(inboundType string, body []byte) (any, error) {
	switch inboundType {
	case C.TypeShadowsocks:
		var user option.ShadowsocksUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeVMess:
		var user option.VMessUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeTrojan:
		var user option.TrojanUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeVLESS:
		var user option.VLESSUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeHysteria2:
		var user option.Hysteria2User
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeHysteria:
		var user option.HysteriaUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeTUIC:
		var user option.TUICUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeSSH:
		var user option.SSHUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeMieru:
		var user option.MieruUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeMTProto:
		var user option.MTProtoUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeShadowTLS:
		var user option.ShadowTLSUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeAnyTLS:
		var user option.AnyTLSUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeSnell:
		var user option.SnellUser
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	case C.TypeNaive, C.TypeSOCKS, C.TypeHTTP, C.TypeMixed:
		var user auth.User
		if err := json.Unmarshal(body, &user); err != nil {
			return nil, err
		}
		return user, nil
	default:
		return nil, newError("protocol " + inboundType + " does not support users")
	}
}

func getUserName(user any) string {
	switch u := user.(type) {
	case option.ShadowsocksUser:
		return u.Name
	case option.VMessUser:
		return u.Name
	case option.TrojanUser:
		return u.Name
	case option.VLESSUser:
		return u.Name
	case option.Hysteria2User:
		return u.Name
	case option.HysteriaUser:
		return u.Name
	case option.TUICUser:
		return u.Name
	case option.SSHUser:
		return u.User
	case option.MieruUser:
		return u.Name
	case option.MTProtoUser:
		return u.Name
	case option.ShadowTLSUser:
		return u.Name
	case option.AnyTLSUser:
		return u.Name
	case option.SnellUser:
		return u.Name
	case auth.User:
		return u.Username
	default:
		return ""
	}
}

func addUserToInbound(inbound *option.Inbound, user any) error {
	switch inbound.Type {
	case C.TypeShadowsocks:
		opts := inbound.Options.(*option.ShadowsocksInboundOptions)
		opts.Users = append(opts.Users, user.(option.ShadowsocksUser))
	case C.TypeVMess:
		opts := inbound.Options.(*option.VMessInboundOptions)
		opts.Users = append(opts.Users, user.(option.VMessUser))
	case C.TypeTrojan:
		opts := inbound.Options.(*option.TrojanInboundOptions)
		opts.Users = append(opts.Users, user.(option.TrojanUser))
	case C.TypeVLESS:
		opts := inbound.Options.(*option.VLESSInboundOptions)
		opts.Users = append(opts.Users, user.(option.VLESSUser))
	case C.TypeHysteria2:
		opts := inbound.Options.(*option.Hysteria2InboundOptions)
		opts.Users = append(opts.Users, user.(option.Hysteria2User))
	case C.TypeHysteria:
		opts := inbound.Options.(*option.HysteriaInboundOptions)
		opts.Users = append(opts.Users, user.(option.HysteriaUser))
	case C.TypeTUIC:
		opts := inbound.Options.(*option.TUICInboundOptions)
		opts.Users = append(opts.Users, user.(option.TUICUser))
	case C.TypeSSH:
		opts := inbound.Options.(*option.SSHInboundOptions)
		opts.Users = append(opts.Users, user.(option.SSHUser))
	case C.TypeMieru:
		opts := inbound.Options.(*option.MieruInboundOptions)
		opts.Users = append(opts.Users, user.(option.MieruUser))
	case C.TypeMTProto:
		opts := inbound.Options.(*option.MTProtoInboundOptions)
		opts.Users = append(opts.Users, user.(option.MTProtoUser))
	case C.TypeShadowTLS:
		opts := inbound.Options.(*option.ShadowTLSInboundOptions)
		opts.Users = append(opts.Users, user.(option.ShadowTLSUser))
	case C.TypeAnyTLS:
		opts := inbound.Options.(*option.AnyTLSInboundOptions)
		opts.Users = append(opts.Users, user.(option.AnyTLSUser))
	case C.TypeSnell:
		opts := inbound.Options.(*option.SnellInboundOptions)
		opts.Users = append(opts.Users, user.(option.SnellUser))
	case C.TypeNaive:
		opts := inbound.Options.(*option.NaiveInboundOptions)
		opts.Users = append(opts.Users, user.(auth.User))
	case C.TypeSOCKS:
		opts := inbound.Options.(*option.SocksInboundOptions)
		opts.Users = append(opts.Users, user.(auth.User))
	case C.TypeHTTP:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		opts.Users = append(opts.Users, user.(auth.User))
	case C.TypeMixed:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		opts.Users = append(opts.Users, user.(auth.User))
	default:
		return newError("protocol " + inbound.Type + " does not support users")
	}
	return nil
}

func removeUserFromInbound(inbound *option.Inbound, name string) error {
	switch inbound.Type {
	case C.TypeShadowsocks:
		opts := inbound.Options.(*option.ShadowsocksInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeVMess:
		opts := inbound.Options.(*option.VMessInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeTrojan:
		opts := inbound.Options.(*option.TrojanInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeVLESS:
		opts := inbound.Options.(*option.VLESSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeHysteria2:
		opts := inbound.Options.(*option.Hysteria2InboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeHysteria:
		opts := inbound.Options.(*option.HysteriaInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeTUIC:
		opts := inbound.Options.(*option.TUICInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeSSH:
		opts := inbound.Options.(*option.SSHInboundOptions)
		for i, u := range opts.Users {
			if u.User == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeMieru:
		opts := inbound.Options.(*option.MieruInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeMTProto:
		opts := inbound.Options.(*option.MTProtoInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeShadowTLS:
		opts := inbound.Options.(*option.ShadowTLSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeAnyTLS:
		opts := inbound.Options.(*option.AnyTLSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeSnell:
		opts := inbound.Options.(*option.SnellInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeNaive:
		opts := inbound.Options.(*option.NaiveInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeSOCKS:
		opts := inbound.Options.(*option.SocksInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeHTTP:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	case C.TypeMixed:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users = append(opts.Users[:i], opts.Users[i+1:]...)
				return nil
			}
		}
	default:
		return newError("protocol " + inbound.Type + " does not support users")
	}
	return ErrNotFound
}

func replaceUserInInbound(inbound *option.Inbound, name string, user any) error {
	switch inbound.Type {
	case C.TypeShadowsocks:
		opts := inbound.Options.(*option.ShadowsocksInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.ShadowsocksUser)
				return nil
			}
		}
	case C.TypeVMess:
		opts := inbound.Options.(*option.VMessInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.VMessUser)
				return nil
			}
		}
	case C.TypeTrojan:
		opts := inbound.Options.(*option.TrojanInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.TrojanUser)
				return nil
			}
		}
	case C.TypeVLESS:
		opts := inbound.Options.(*option.VLESSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.VLESSUser)
				return nil
			}
		}
	case C.TypeHysteria2:
		opts := inbound.Options.(*option.Hysteria2InboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.Hysteria2User)
				return nil
			}
		}
	case C.TypeHysteria:
		opts := inbound.Options.(*option.HysteriaInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.HysteriaUser)
				return nil
			}
		}
	case C.TypeTUIC:
		opts := inbound.Options.(*option.TUICInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.TUICUser)
				return nil
			}
		}
	case C.TypeSSH:
		opts := inbound.Options.(*option.SSHInboundOptions)
		for i, u := range opts.Users {
			if u.User == name {
				opts.Users[i] = user.(option.SSHUser)
				return nil
			}
		}
	case C.TypeMieru:
		opts := inbound.Options.(*option.MieruInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.MieruUser)
				return nil
			}
		}
	case C.TypeMTProto:
		opts := inbound.Options.(*option.MTProtoInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.MTProtoUser)
				return nil
			}
		}
	case C.TypeShadowTLS:
		opts := inbound.Options.(*option.ShadowTLSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.ShadowTLSUser)
				return nil
			}
		}
	case C.TypeAnyTLS:
		opts := inbound.Options.(*option.AnyTLSInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.AnyTLSUser)
				return nil
			}
		}
	case C.TypeSnell:
		opts := inbound.Options.(*option.SnellInboundOptions)
		for i, u := range opts.Users {
			if u.Name == name {
				opts.Users[i] = user.(option.SnellUser)
				return nil
			}
		}
	case C.TypeNaive:
		opts := inbound.Options.(*option.NaiveInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users[i] = user.(auth.User)
				return nil
			}
		}
	case C.TypeSOCKS:
		opts := inbound.Options.(*option.SocksInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users[i] = user.(auth.User)
				return nil
			}
		}
	case C.TypeHTTP:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users[i] = user.(auth.User)
				return nil
			}
		}
	case C.TypeMixed:
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		for i, u := range opts.Users {
			if u.Username == name {
				opts.Users[i] = user.(auth.User)
				return nil
			}
		}
	default:
		return newError("protocol " + inbound.Type + " does not support users")
	}
	return ErrNotFound
}

// User CRUD HTTP handlers

// @Summary List users
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Success 200 {array} object
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag}/users [get]
func listUsers(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for _, inbound := range options.Inbounds {
			if inbound.Tag == tag {
				users, err := getInboundUsers(inbound)
				if err != nil {
					render.Status(r, http.StatusBadRequest)
					render.JSON(w, r, newError(err.Error()))
					return
				}
				render.JSON(w, r, users)
				return
			}
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// @Summary Get user by name
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param name path string true "User name"
// @Success 200 {object} object
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag}/users/{name} [get]
func getUser(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		name := getEscapeParam(r, "name")
		options, err := s.configManager.ReadConfig()
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		for _, inbound := range options.Inbounds {
			if inbound.Tag == tag {
				users, err := getInboundUsers(inbound)
				if err != nil {
					render.Status(r, http.StatusBadRequest)
					render.JSON(w, r, newError(err.Error()))
					return
				}
				for _, user := range users {
					if getUserName(user) == name {
						render.JSON(w, r, user)
						return
					}
				}
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
		}
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
	}
}

// @Summary Add user
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param user body object true "User object (fields depend on protocol)"
// @Success 201 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 409 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag}/users [post]
func addUser(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, inbound := range options.Inbounds {
				if inbound.Tag == tag {
					user, err := unmarshalUser(inbound.Type, body)
					if err != nil {
						return options, err
					}
					userName := getUserName(user)
					if userName == "" {
						return options, newError("user name is required")
					}
					existing, err := getInboundUsers(inbound)
					if err != nil {
						return options, err
					}
					for _, eu := range existing {
						if getUserName(eu) == userName {
							return options, &conflictError{Message: "user " + userName + " already exists"}
						}
					}
					err = addUserToInbound(&options.Inbounds[i], user)
					if err != nil {
						return options, err
					}
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.Status(r, http.StatusCreated)
		render.JSON(w, r, render.M{"message": "user added"})
	}
}

// @Summary Update user
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param name path string true "User name"
// @Param user body object true "Updated user object"
// @Success 200 {object} object{message=string}
// @Failure 400 {object} HTTPError
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag}/users/{name} [put]
func updateUser(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		name := getEscapeParam(r, "name")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		err = s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, inbound := range options.Inbounds {
				if inbound.Tag == tag {
					user, err := unmarshalUser(inbound.Type, body)
					if err != nil {
						return options, err
					}
					err = replaceUserInInbound(&options.Inbounds[i], name, user)
					if err != nil {
						return options, err
					}
					return options, nil
				}
			}
			return options, ErrNotFound
		})
		if err != nil {
			writeModifyError(w, r, err)
			return
		}
		render.JSON(w, r, render.M{"message": "user updated"})
	}
}

// @Summary Remove user
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Param tag path string true "Inbound tag"
// @Param name path string true "User name"
// @Success 204
// @Failure 404 {object} HTTPError
// @Failure 500 {object} HTTPError
// @Router /manage/inbounds/{tag}/users/{name} [delete]
func deleteUser(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tag := getEscapeParam(r, "tag")
		name := getEscapeParam(r, "name")
		err := s.configManager.ModifyConfig(func(options option.Options) (option.Options, error) {
			for i, inbound := range options.Inbounds {
				if inbound.Tag == tag {
					err := removeUserFromInbound(&options.Inbounds[i], name)
					if err != nil {
						return options, err
					}
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

type conflictError struct {
	Message string
}

func (e *conflictError) Error() string {
	return e.Message
}

func writeModifyError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case *conflictError:
		render.Status(r, http.StatusConflict)
	default:
		if err == ErrNotFound {
			render.Status(r, http.StatusNotFound)
		} else {
			render.Status(r, http.StatusInternalServerError)
		}
	}
	render.JSON(w, r, newError(err.Error()))
}
