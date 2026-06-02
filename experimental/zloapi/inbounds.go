package zloapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/vless"
)

func parseInboundTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "tag")
		ctx := context.WithValue(r.Context(), CtxKeyInboundTag, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findInboundByTag(server *Server) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := r.Context().Value(CtxKeyInboundTag).(string)
			inbound, exist := server.inbound.Get(name)
			if !exist {
				render.Status(r, http.StatusNotFound)
				render.JSON(w, r, ErrNotFound)
				return
			}
			ctx := context.WithValue(r.Context(), CtxKeyInbound, inbound)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func getInboundUsers(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		inbound, _ := r.Context().Value(CtxKeyInbound).(adapter.Inbound)

		switch inbound.Type() {
		case C.TypeHysteria2:
			render.JSON(w, r, hysteria2.GetHysteria2Users(inbound))
		case C.TypeVLESS:
			render.JSON(w, r, vless.GetVlessUsers(inbound))
		default:
			render.Status(r, http.StatusUnprocessableEntity)
			render.JSON(w, r, ErrUnsupportedInbound)
		}
	}
}

func setInboundUsers(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		inbound, _ := r.Context().Value(CtxKeyInbound).(adapter.Inbound)

		switch inbound.Type() {
		case C.TypeHysteria2:
			var req []option.Hysteria2User
			if err := render.DecodeJSON(r.Body, &req); err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, ErrBadRequest)
				return
			}
			hysteria2.SetHysteria2Users(inbound, req)
			render.NoContent(w, r)
		case C.TypeVLESS:
			var req []option.VLESSUser
			if err := render.DecodeJSON(r.Body, &req); err != nil {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, ErrBadRequest)
				return
			}
			vless.SetVlessUsers(inbound, req)
			render.NoContent(w, r)
		default:
			render.Status(r, http.StatusUnprocessableEntity)
			render.JSON(w, r, ErrUnsupportedInbound)
		}
	}
}

func inboundRouter(server *Server) http.Handler {
	r := chi.NewRouter()

	r.Route("/{tag}", func(r chi.Router) {
		r.Use(parseInboundTag, findInboundByTag(server))
		r.Get("/users", getInboundUsers(server))
		r.Put("/users", setInboundUsers(server))
	})

	return r
}
