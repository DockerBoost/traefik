package blacklist

import (
	"encoding/json"
	"github.com/traefik/traefik/v2/pkg/log"
	"net/http"
)

func ApiGetHandler(rw http.ResponseWriter, request *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	if ip := request.URL.Query().Get("ip"); ip != "" {
		apiGetIp(ip, rw, request)
	} else {
		apiStats(rw, request)
	}

}

func apiGetIp(ip string, rw http.ResponseWriter, request *http.Request) {
	ipStatI, ok := GetInstance().IpList.Peek(ip)
	if !ok {
		http.Error(rw, "no ip", http.StatusNotFound)
		return
	}
	ipStat := ipStatI.(*IpStats)

	result := map[string]interface{}{
		"Total": ipStat.Total,
		"Average": ipStat.Average,
		"TotalPeriodStats": ipStat.TotalPeriodStats,
		"AveragePeriodStats": ipStat.AveragePeriodStats,
		"Blocked": ipStat.Blocked.Load(),
		"Comment": ipStat.Comment.Load(),
	}
	minStats := map[int64]interface{}{}

	ipStat.MinuteStats.Map(func(item *CacheItem) bool {
		v := item.Value.(*SliceStats)
		minStats[item.Key.(int64)*60] = map[string]interface{}{
			"Code2xx": v.Code2xx.Load(),
			"Code404": v.Code404.Load(),
			"Code429": v.Code429.Load(),
			"Head": v.Head.Load(),
			"Post": v.Post.Load(),
			"Total": v.Total.Load(),
		}

		return true
	})
	result["MinuteStats"] = minStats

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "\t")
	err := enc.Encode(result)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		writeError(rw, err.Error(), http.StatusInternalServerError)
	}
}

func apiStats(rw http.ResponseWriter, request *http.Request) {
	result := GetInstance().GetStats()
	enc := json.NewEncoder(rw)
	enc.SetIndent("", "\t")
	err := enc.Encode(result)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		writeError(rw, err.Error(), http.StatusInternalServerError)
	}
}

func ApiPostHandler(rw http.ResponseWriter, request *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	decoder := json.NewDecoder(request.Body)
	var req struct {
		Ip      string
		Ips     []string
		Comment string
		Ban     bool
	}
	err := decoder.Decode(&req)
	if err != nil {
		log.FromContext(request.Context()).Error(err)
		writeError(rw, err.Error(), http.StatusBadRequest)
	}

	if req.Ip != "" {
		req.Ips = []string{req.Ip}
	}
	if len(req.Ips) > 0 {
		bl := GetInstance()
		for _, ip := range req.Ips {
			bl.Ban(ip, req.Comment, req.Ban)
		}
	}
	rw.Write([]byte(`"OK"`))
}



type apiError struct {
	Message string `json:"message"`
}

func writeError(rw http.ResponseWriter, msg string, code int) {
	data, err := json.MarshalIndent(apiError{Message: msg}, "", "\t")
	if err != nil {
		http.Error(rw, msg, code)
		return
	}

	http.Error(rw, string(data), code)
}
