package blacklist

import (
	"sync"
	"time"
)

// this runs every minute
func (list *Blacklist) collect() {
	currentMinuteEpoch := time.Now().Unix() / 60
	newStats := map[string]SummedStats{}
	m := sync.Mutex{}

	list.IpList.Each(CollectConcurrency, func(key interface{}, value interface{}) error {
		ip := key.(string)
		stats := value.(*IpStats)

		summed, err := collectExactIp(ip, stats, currentMinuteEpoch)

		m.Lock()
		defer m.Unlock()
		newStats[ip] = summed

		return err
	})

	list.listMutex.Lock()
	list.listMutex.Unlock()
	list.AggregatedIpStats = newStats

}

func collectExactIp(ip string, stats *IpStats, minuteEpoch int64) (sum SummedStats, err error) {
	stats.m.Lock()
	defer stats.m.Unlock()

	keys := stats.MinuteStats.Keys()
	minMinuteEpoch := minuteEpoch - MinutesToStore
	summed := SummedStats{
		Total:   stats.TotalPeriodStats,
		Average: stats.AveragePeriodStats,
	}

	stats.AveragePeriodStats.Code404 = 0
	stats.AveragePeriodStats.Code429 = 0
	stats.AveragePeriodStats.Code2xx = 0
	stats.AveragePeriodStats.Head = 0
	stats.AveragePeriodStats.Post = 0
	stats.AveragePeriodStats.Total = 0
	stats.Average = 0

	stats.TotalPeriodStats.Code404 = 0
	stats.TotalPeriodStats.Code429 = 0
	stats.TotalPeriodStats.Code2xx = 0
	stats.TotalPeriodStats.Head = 0
	stats.TotalPeriodStats.Post = 0
	stats.TotalPeriodStats.Total = 0
	stats.Total = 0

	summed.MinutesStored = 0

	for _, key := range keys {
		intKey := key.(int64)
		if intKey < minMinuteEpoch {
			stats.MinuteStats.Remove(intKey)
			continue
		}

		minuteStatI, ok := stats.MinuteStats.Peek(key)
		if !ok {
			continue
		}
		summed.MinutesStored++

		if intKey < summed.FirstMinute || summed.FirstMinute == 0{
			summed.FirstMinute = intKey
		}
		if summed.LastMinute == 0 || intKey > summed.LastMinute {
			summed.LastMinute = intKey
		}

		minuteStat := minuteStatI.(*SliceStats)
		stats.TotalPeriodStats.Code404 += minuteStat.Code404.Load()
		stats.TotalPeriodStats.Code429 += minuteStat.Code429.Load()
		stats.TotalPeriodStats.Code2xx += minuteStat.Code2xx.Load()
		stats.TotalPeriodStats.Post += minuteStat.Post.Load()
		stats.TotalPeriodStats.Head += minuteStat.Head.Load()
		stats.TotalPeriodStats.Total += minuteStat.Total.Load()
		stats.Total += minuteStat.Total.Load()
	}

	if summed.MinutesStored > 0 {
		stats.AveragePeriodStats.Code404 += stats.TotalPeriodStats.Code404 / summed.MinutesStored
		stats.AveragePeriodStats.Code429 += stats.TotalPeriodStats.Code429 / summed.MinutesStored
		stats.AveragePeriodStats.Code2xx += stats.TotalPeriodStats.Code2xx / summed.MinutesStored
		stats.AveragePeriodStats.Post += stats.TotalPeriodStats.Post / summed.MinutesStored
		stats.AveragePeriodStats.Head += stats.TotalPeriodStats.Head / summed.MinutesStored
		stats.AveragePeriodStats.Total += stats.Total / summed.MinutesStored
		stats.Average = float64(stats.Total) / float64(summed.MinutesStored)
	}

	// TODO: Here we can place autoban rules on custom ratelimit

	summed.LastMinute *= 60
	summed.FirstMinute *= 60
	return summed, nil
}

