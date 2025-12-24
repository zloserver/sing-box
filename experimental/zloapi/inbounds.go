package zloapi

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
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
		inbound := r.Context().Value(CtxKeyInbound).(adapter.TCPInjectableInbound)

		render.JSON(w, r, vless.GetVlessUsers(inbound))
	}
}

func setInboundUsers(server *Server) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var req []option.VLESSUser
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}

		inbound := r.Context().Value(CtxKeyInbound).(adapter.TCPInjectableInbound)
		vless.SetVlessUsers(inbound, req)
		render.NoContent(w, r)
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
