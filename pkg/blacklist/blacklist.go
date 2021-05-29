package blacklist

import (
	"go.uber.org/atomic"
	"sync"
	"time"
)

const MaxSources = 2<<12
const MinutesToStore = 30
const CollectConcurrency = 64
const DefaultIpStoreDuration = time.Hour
const MethodPost = "post"
const MethodHead = "head"
const DefaultBanDuration = time.Minute * 30

//const CollectInterval = 60000
const CollectInterval = 10000

type SliceStats struct {
	Code2xx atomic.Uint64
	Code404 atomic.Uint64
	Code429 atomic.Uint64
	Head    atomic.Uint64
	Post    atomic.Uint64
	Total   atomic.Uint64
}

type PlainStats struct {
	Code2xx uint64
	Code404 uint64
	Code429 uint64
	Head    uint64
	Post    uint64
	Total   uint64
}

type SummedStats struct {
	Total         *PlainStats
	Average       *PlainStats
	MinutesStored uint64
	FirstMinute   int64
	LastMinute    int64
}

type IpStats struct {
	MinuteStats        *LRUCache
	TotalPeriodStats   *PlainStats
	AveragePeriodStats *PlainStats
	Total              uint64
	Average            float64
	m                  sync.RWMutex
	Blocked            atomic.Bool
	BlockExpires       atomic.Int64
	BlockMinute        int64
	Comment            atomic.String
}

type Blacklist struct {
	IpList            *LRUCache
	AggregatedIpStats map[string]SummedStats
	AggregatedBanList map[string]string
	BannedIps         sync.Map
	listMutex         sync.RWMutex
	aggregateMutex    sync.RWMutex
}

var blackListInstance *Blacklist

func GetInstance() *Blacklist {
	if blackListInstance == nil {
		blackListInstance = NewBlacklist()
	}
	return blackListInstance
}

func NewBlacklist() *Blacklist {
	list := &Blacklist{
		IpList:            NewLRUCache(MaxSources),
		AggregatedIpStats: map[string]SummedStats{},
		AggregatedBanList: map[string]string{},
		BannedIps:         sync.Map{},
	}
	setInterval(list.collect, CollectInterval, true)
	return list
}

func (list *Blacklist) GetStats() map[string]interface{} {
	list.listMutex.RLock()
	list.aggregateMutex.RLock()
	defer list.listMutex.RUnlock()
	defer list.aggregateMutex.RUnlock()

	return map[string]interface{}{
		"AggregatedIpStats": list.AggregatedIpStats,
		"AggregatedBanList": list.AggregatedBanList,
	}
}

func setInterval(someFunc func(), milliseconds int, async bool) chan bool {

	// How often to fire the passed in function
	// in milliseconds
	interval := time.Duration(milliseconds) * time.Millisecond

	// Setup the ticket and the channel to signal
	// the ending of the interval
	ticker := time.NewTicker(interval)
	clear := make(chan bool)

	// Put the selection in a go routine
	// so that the for loop is none blocking
	go func() {
		for {

			select {
			case <-ticker.C:
				if async {
					// This won't block
					go someFunc()
				} else {
					// This will block
					someFunc()
				}
			case <-clear:
				ticker.Stop()
				return
			}

		}
	}()

	// We return the channel so we can pass in
	// a value to it to clear the interval
	return clear

}
