package blacklist

import (
	"github.com/traefik/traefik/v2/pkg/log"
	"sync"
	"time"
)

// this runs every minute
func (list *Blacklist) collect() {
	log.WithoutContext().Debugf("\n\nRunning collect....\n=========================\n")
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


	verdict := calculateVerdict(stats, summed.MinutesStored)
	log.WithoutContext().Debugf("\n\nCalculated verdict for %s is %s\n", ip, verdict)
	if verdict != "" {
		if stats.Blocked.Load() == true {
			// ip was already blocked
			log.WithoutContext().Debugf("ip was already blocked\n")
			if stats.BlockMinute == summed.LastMinute {
				// we blocked on last minute of our histogram
				// don't update block time

				// check if we can unban already banned thing
				log.WithoutContext().Debugf("unban check@117\n")
				checkUnban(ip, stats, minuteEpoch)
			} else {
				// we blocked earlier and we have new stats
				// with this new stats we have same verdict
				// so update ban with new time
				banIpStat(ip, verdict)
			}
		} else {
			// new block
			log.WithoutContext().Debugf("new block\n")
			banIpStat(ip, verdict)
		}
	} else {
		// new verdict is not to ban

		// check if we can unban already banned thing
		log.WithoutContext().Debugf("unban check@133\n")
		checkUnban(ip, stats, minuteEpoch)
	}

	summed.LastMinute *= 60
	summed.FirstMinute *= 60

	return summed, nil
}

func banIpStat(ip string, verdict string) {
	log.WithoutContext().Debugf("Ban verdict for %s is %s\n", ip, verdict)
	GetInstance().Ban(ip, "rate-limit: " + verdict, true, DefaultBanDuration)
}

func checkUnban(ip string, stats *IpStats, minuteEpoch int64) {
	if stats.Blocked.Load() == true {
		log.WithoutContext().Debugf("UnBan check for %s expires at %s\nNow is %s\n", ip, time.Unix(stats.BlockExpires.Load(), 0).Format(time.RFC1123), time.Now().Format(time.RFC1123))
		if stats.Blocked.Load() == true && stats.BlockExpires.Load() < minuteEpoch*60 {
			log.WithoutContext().Debugf("Unbanning %s\n", ip)
			GetInstance().Ban(ip, "", false, 0)
		} else {
			log.WithoutContext().Debugf("Not unbanning\n")
		}
	}
}