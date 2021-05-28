package blacklist

import (
	"go.uber.org/atomic"
	"sync"
	"time"
)

func (list *Blacklist) PlaceRequest(ip string, code int, method string) {
	var stats *IpStats
	statsI, ok := list.IpList.Get(ip)
	if ok {
		stats = statsI.(*IpStats)
	} else {
		stats = &IpStats{
			MinuteStats:        NewLRUCache(MinutesToStore),
			TotalPeriodStats:   &PlainStats{},
			AveragePeriodStats: &PlainStats{},
			Total:              0,
			Average:            0,
			m:                  sync.RWMutex{},
			Blocked:            atomic.Bool{},
			Comment:            atomic.String{},
		}
		list.IpList.AddWithTTL(ip, stats, DefaultIpStoreDuration)
	}
	stats.PlaceRequest(ip, code, method)
}

func (stats *IpStats) PlaceRequest(ip string, code int, method string) {
	currentMinuteEpoch := time.Now().Unix() / 60
	var minStats *SliceStats
	minStatsI, ok := stats.MinuteStats.Get(currentMinuteEpoch)
	if ok {
		minStats = minStatsI.(*SliceStats)
	} else {
		minStats = &SliceStats{}
		stats.MinuteStats.AddWithTTL(currentMinuteEpoch, minStats, time.Minute*(MinutesToStore+2))
	}
	minStats.Total.Inc()
	if code >= 200 && code <= 299 {
		minStats.Code2xx.Inc()
	}
	if code == 404 {
		minStats.Code404.Inc()
	}
	if code == 429 {
		minStats.Code429.Inc()
	}
	if method == MethodPost {
		minStats.Post.Inc()
	}
	if method == MethodHead {
		minStats.Head.Inc()
	}

}