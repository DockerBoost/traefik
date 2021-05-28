package blacklist

import (
	"go.uber.org/atomic"
	"sync"
)

func (list *Blacklist) Ban(ip string, comment string, ban bool) {
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
			Comment:            atomic.String{},
		}
		list.IpList.AddWithTTL(ip, stats, DefaultIpStoreDuration)
	}
	stats.Blocked.Store(ban)
	if len(comment) > 0 {
		stats.Comment.Store(comment)
	}
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



