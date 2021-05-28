package blacklist

import (
	"encoding/json"
	"github.com/traefik/traefik/v2/pkg/log"
	"net/http"
)

func DebugBl(source string, balancerName string, rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "\t")
	result := map[string]interface{}{
		"s": source,
		"x": r.Header.Get("X-Forwarded-For"),
		"lb": balancerName,
	}
	err := enc.Encode(result)
	if err != nil {
		log.FromContext(r.Context()).Error(err)
		writeError(rw, err.Error(), http.StatusInternalServerError)
	}
}
