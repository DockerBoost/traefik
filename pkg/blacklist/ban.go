package blacklist

import (
	"go.uber.org/atomic"
	"sync"
	"time"
)

func (list *Blacklist) Ban(ip string, comment string, ban bool, duration time.Duration) {
	var stats *IpStats

	statsI, ok := list.IpList.Get(ip)
	go list.placeBan(ip, comment, ban)

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
			BlockExpires:       atomic.Int64{},
			BlockMinute:        0,
			Comment:            atomic.String{},
		}
		list.IpList.AddWithTTL(ip, stats, DefaultIpStoreDuration)
	}
	stats.Blocked.Store(ban)
	if len(comment) > 0 {
		stats.Comment.Store(comment)
	}
	stats.BlockMinute = time.Now().Unix() / 60
	stats.BlockExpires.Store(time.Now().Add(duration).Unix())
	list.BannedIps.Store(ip, ban)
}

func (list *Blacklist) placeBan(ip string, comment string, ok bool) {
	list.aggregateMutex.Lock()
	defer list.aggregateMutex.Unlock()
	if ok {
		list.AggregatedBanList[ip] = comment
	} else {
		delete(list.AggregatedBanList, ip)
	}
}

func (list *Blacklist) IsBanned(ip string) bool {
	v, ok := list.BannedIps.Load(ip)
	if !ok {
		return false
	}
	return v.(bool)
}

func calculateVerdict(stats *IpStats, minutesStored uint64) string {
	if minutesStored == 0 {
		return ""
	}

	if stats.AveragePeriodStats.Code429 > 50 {
		return "Avg.429 gt 50"
	}
	if stats.AveragePeriodStats.Total > 5000 {
		return "Avg.Total gt 5000"
	}
	if stats.AveragePeriodStats.Code404 > 500 {
		return "Avg.404 gt 500"
	}
	if stats.AveragePeriodStats.Code2xx > 3500 {
		return "Avg.2xx gt 3500"
	}

	return ""
}
