package blacklist


import (
	"container/list"
	"github.com/traefik/traefik/v2/pkg/blacklist/clock"
	"github.com/traefik/traefik/v2/pkg/blacklist/syncutil"
	"sync"

)

// Holds stats collected about the cache
type LRUCacheStats struct {
	Size int64
	Miss int64
	Hit  int64
}

// Cache is an thread safe LRU cache that also supports optional TTL expiration
// You can use an non thread safe version of this
type LRUCache struct {
	// MaxEntries is the maximum number of cache entries before
	// an item is evicted. Zero means no limit.
	MaxEntries int

	// OnEvicted optionally specifies a callback function to be
	// executed when an entry is purged from the cache.
	OnEvicted func(key Key, value interface{})

	mutex sync.Mutex
	stats LRUCacheStats
	ll    *list.List
	cache map[interface{}]*list.Element
}

// A Key may be any value that is comparable. See http://golang.org/ref/spec#Comparison_operators
type Key interface{}

type CacheItem struct {
	Key      Key
	Value    interface{}
	ExpireAt *clock.Time
}

// New creates a new Cache.
// If maxEntries is zero, the cache has no limit and it's assumed
// that eviction is done by the caller.
func NewLRUCache(maxEntries int) *LRUCache {
	return &LRUCache{
		MaxEntries: maxEntries,
		ll:         list.New(),
		cache:      make(map[interface{}]*list.Element),
	}
}

// Add or Update a value in the cache, return true if the key already existed
func (c *LRUCache) Add(key Key, value interface{}) bool {
	return c.addRecord(&CacheItem{Key: key, Value: value})
}

// Adds a value to the cache with a TTL
func (c *LRUCache) AddWithTTL(key Key, value interface{}, TTL clock.Duration) bool {
	expireAt := clock.Now().UTC().Add(TTL)
	return c.addRecord(&CacheItem{
		Key:      key,
		Value:    value,
		ExpireAt: &expireAt,
	})
}

// Adds a value to the cache.
func (c *LRUCache) addRecord(record *CacheItem) bool {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	// If the key already exist, set the new value
	if ee, ok := c.cache[record.Key]; ok {
		c.ll.MoveToFront(ee)
		temp := ee.Value.(*CacheItem)
		*temp = *record
		return true
	}

	ele := c.ll.PushFront(record)
	c.cache[record.Key] = ele
	if c.MaxEntries != 0 && c.ll.Len() > c.MaxEntries {
		c.removeOldest()
	}
	return false
}

// Get looks up a key's value from the cache.
func (c *LRUCache) Get(key Key) (value interface{}, ok bool) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	if ele, hit := c.cache[key]; hit {
		entry := ele.Value.(*CacheItem)

		// If the entry has expired, remove it from the cache
		if entry.ExpireAt != nil && entry.ExpireAt.Before(clock.Now().UTC()) {
			c.removeElement(ele)
			c.stats.Miss++
			return
		}
		c.stats.Hit++
		c.ll.MoveToFront(ele)
		return entry.Value, true
	}
	c.stats.Miss++
	return
}

// Remove removes the provided key from the cache.
func (c *LRUCache) Remove(key Key) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	if ele, hit := c.cache[key]; hit {
		c.removeElement(ele)
	}
}

// RemoveOldest removes the oldest item from the cache.
func (c *LRUCache) removeOldest() {
	ele := c.ll.Back()
	if ele != nil {
		c.removeElement(ele)
	}
}

func (c *LRUCache) removeElement(e *list.Element) {
	c.ll.Remove(e)
	kv := e.Value.(*CacheItem)
	delete(c.cache, kv.Key)
	if c.OnEvicted != nil {
		c.OnEvicted(kv.Key, kv.Value)
	}
}

// Len returns the number of items in the cache.
func (c *LRUCache) Size() int {
	defer c.mutex.Unlock()
	c.mutex.Lock()
	return c.ll.Len()
}

// Returns stats about the current state of the cache
func (c *LRUCache) Stats() LRUCacheStats {
	defer func() {
		c.stats = LRUCacheStats{}
		c.mutex.Unlock()
	}()
	c.mutex.Lock()
	c.stats.Size = int64(len(c.cache))
	return c.stats
}

// Get a list of keys at this point in time
func (c *LRUCache) Keys() (keys []interface{}) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	for key := range c.cache {
		keys = append(keys, key)
	}
	return
}

// Get the value without updating the expiration or last used or stats
func (c *LRUCache) Peek(key interface{}) (value interface{}, ok bool) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	if ele, hit := c.cache[key]; hit {
		entry := ele.Value.(*CacheItem)
		return entry.Value, true
	}
	return nil, false
}

// Processes each item in the cache in a thread safe way, such that the cache can be in use
// while processing items in the cache. Processing the cache with `Each()` does not update
// the expiration or last used.
func (c *LRUCache) Each(concurrent int, callBack func(key interface{}, value interface{}) error) []error {
	fanOut := syncutil.NewFanOut(concurrent)
	keys := c.Keys()

	for _, key := range keys {
		fanOut.Run(func(key interface{}) error {
			value, ok := c.Peek(key)
			if !ok {
				// Key disappeared during cache iteration, This can occur as
				// expiration and removal can happen during iteration
				return nil
			}

			err := callBack(key, value)
			if err != nil {
				return err
			}
			return nil
		}, key)
	}

	// Wait for all the routines to complete
	errs := fanOut.Wait()
	if errs != nil {
		return errs
	}
	return nil
}

// Map modifies the cache according to the mapping function, If mapping returns false the
// item is removed from the cache and `OnEvicted` is called if defined. Map claims exclusive
// access to the cache; as such concurrent access will block until Map returns.
func (c *LRUCache) Map(mapping func(item *CacheItem) bool) {
	defer c.mutex.Unlock()
	c.mutex.Lock()

	for _, v := range c.cache {
		if !mapping(v.Value.(*CacheItem)) {
			c.removeElement(v)
		}
	}
}

