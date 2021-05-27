package blacklist

import (
	"encoding/json"
	"github.com/traefik/traefik/v2/pkg/log"
	"go.uber.org/atomic"
	"net/http"
	"sync"
	"time"
)

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
	Total   *PlainStats
	Average *PlainStats
}

type IpStats struct {
	MinuteStats        *LRUCache
	TotalPeriodStats   *PlainStats
	AveragePeriodStats *PlainStats
	Total              uint64
	Average            float64
	m                  sync.RWMutex
	Blocked            atomic.Bool
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

const MaxSources = 65536
const MinutesToStore = 30
const CollectConcurrency = 64
const DefaultIpStoreDuration = time.Hour
const MethodPost = "post"
const MethodHead = "head"
//const CollectInterval = 60000
const CollectInterval = 10000

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
		stats.MinuteStats.AddWithTTL(currentMinuteEpoch, minStats, time.Minute * (MinutesToStore+2))
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

	stats.AveragePeriodStats.Code404 = 0
	stats.AveragePeriodStats.Code429 = 0
	stats.AveragePeriodStats.Code2xx = 0
	stats.AveragePeriodStats.Head = 0
	stats.AveragePeriodStats.Post = 0
	stats.Average = 0

	stats.TotalPeriodStats.Code404 = 0
	stats.TotalPeriodStats.Code429 = 0
	stats.TotalPeriodStats.Code2xx = 0
	stats.TotalPeriodStats.Head = 0
	stats.TotalPeriodStats.Post = 0
	stats.Total = 0

	totalMinutesStored := uint64(0)

	for _, key := range keys {
		intKey := key.(int64)
		if intKey < minMinuteEpoch {
			stats.MinuteStats.Remove(intKey)
			continue
		}
		minuteStatI, ok := stats.MinuteStats.Get(key)
		if !ok {
			continue
		}
		totalMinutesStored++
		minuteStat := minuteStatI.(*SliceStats)
		stats.TotalPeriodStats.Code404 += minuteStat.Code404.Load()
		stats.TotalPeriodStats.Code429 += minuteStat.Code429.Load()
		stats.TotalPeriodStats.Code2xx += minuteStat.Code2xx.Load()
		stats.TotalPeriodStats.Post += minuteStat.Post.Load()
		stats.TotalPeriodStats.Head += minuteStat.Head.Load()
		stats.Total += minuteStat.Total.Load()
	}
	if totalMinutesStored > 0 {
		stats.AveragePeriodStats.Code404 += stats.TotalPeriodStats.Code404 / totalMinutesStored
		stats.AveragePeriodStats.Code429 += stats.TotalPeriodStats.Code429 / totalMinutesStored
		stats.AveragePeriodStats.Code2xx += stats.TotalPeriodStats.Code2xx / totalMinutesStored
		stats.AveragePeriodStats.Post += stats.TotalPeriodStats.Post / totalMinutesStored
		stats.AveragePeriodStats.Head += stats.TotalPeriodStats.Head / totalMinutesStored
		stats.Average = float64(stats.Total) / float64(totalMinutesStored)
	}

	// TODO: Here we can place autoban rules on custom ratelimit

	return SummedStats{
		Total:   stats.TotalPeriodStats,
		Average: stats.AveragePeriodStats,
	}, nil
}

func ApiGetHandler(rw http.ResponseWriter, request *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
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
		Ip string
		Ips []string
		Comment string
		Ban bool
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
