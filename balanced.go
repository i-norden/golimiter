package httplimiter

import (
	"errors"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Structs for internal load balancing
// that adjusts api limits according to overall demand
// Balancer is used to rate the server's aggregated load
type balancer struct {
	med       *rate.Limiter // Trigger to set server load state to medium
	high      *rate.Limiter // Trigger to set server load state to high
	Whitelist struct {      // Whitelist settings
		On         bool          // On or off (default false- off)
		Filename   string        // File location
		UpdateFreq time.Duration // Update frequency (how often it reads file to check for changes; in minutes)
		quitChan   chan bool     // Channel used to stop the background goroutine
		list       []string      // The whitelist as an array
	}
	Blacklist struct { // Blacklist settings
		On         bool          // On or off (default false- off)
		Filename   string        // File location
		UpdateFreq time.Duration // Update frequency (in minutes)
		quitChan   chan bool     // Channel used to stop the background goroutine
		list       []string      // The blacklist as an array
	}
	CleanUp struct { //
		Off      bool          // On or off (default false- on)
		Thres    time.Duration // Time before visitor expires and is removed (in minutes)
		Freq     time.Duration // Cleanup frequency (in minutes)
		quitChan chan bool     // Channel used to stop the background goroutine
	}
	visitors map[string]*visitor // Map to hold the visitor structs for each ip
}

// Class of visitor with limiter settins for differ load conditions
type visitor struct {
	limiters struct {
		low  *rate.Limiter
		med  *rate.Limiter
		high *rate.Limiter
	}
	lastSeen time.Time
}

type state struct {
	low  bool
	med  bool
	high bool
}

// Mutex for locking access to shared data structs
var mtx sync.Mutex

var load state

// Create and return a new balancer
func NewBalancer(med, high int) *balancer {
	var bal balancer
	bal.med = rate.NewLimiter(1, med)
	bal.high = rate.NewLimiter(1, high)
	return &bal
}

// Update state variable based on balancers global limiter states
func (b *balancer) update() {
	mtx.Lock()
	load.set("low")
	if b.med.Allow() == false {
		load.set("med")
	}
	if b.high.Allow() == false {
		load.set("high")
	}
	mtx.Unlock()
}

// Function to get state state
func (s *state) get() (state string) {
	mtx.Lock()
	defer mtx.Unlock()
	if s.low {
		return "low"
	}
	if s.med {
		return "med"
	}
	if s.high {
		return "high"
	}
	return
}

// Function to set state
func (s *state) set(state string) (err error) {
	if state == "low" {
		s.low = true
		s.med = false
		s.high = false
		return
	}
	if state == "med" {
		s.low = false
		s.med = true
		s.high = false
		return
	}
	if state == "high" {
		s.low = false
		s.med = false
		s.high = true
		return
	}
	err = errors.New("Invalid state")
	return
}

func (v *visitor) Allow() bool {
	low := v.limiters.low.Allow()
	med := v.limiters.med.Allow()
	high := v.limiters.high.Allow()
	if load.get() == "low" {
		return low
	}
	if load.get() == "med" {
		return med
	}
	if load.get() == "high" {
		return high
	}
	return false
}

// Function to initialize the internal balancer
func (b *balancer) Init() (err error) {
	return err
}

// Check for current visitor's rate limiter and return it if they have one
// If they don't, call the addVisitor function to assign them a new limiter
func (b *balancer) getVisitor(ip string) (v *visitor) {
	// Update the last seen time for the visitor.
	return
}

// Creates a new limiter and adds it to the visitors map
// with the user's IP address as the key.
func (b *balancer) addVisitor(ip string) (v *visitor) {
	// Create a token bucket limiter that allows base querys/second or burst amount at once
	return
}

// Every minute check the map for visitors that haven't been
// seen for more than x minutes and remove them.
func (b *balancer) cleanupVisitors(quit chan bool) {

}

// Function to update whitelist from a file
func (b *balancer) updateWhitelist(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			mtx.Lock()
			newList, err := readList(b.Whitelist.Filename)
			if err == nil {
				b.Whitelist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * b.Whitelist.UpdateFreq)
		}
	}
}

// Function to update blacklist from a file
func (b *balancer) updateBlacklist(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			mtx.Lock()
			newList, err := readList(b.Blacklist.Filename)
			if err == nil {
				b.Blacklist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * b.Blacklist.UpdateFreq)
		}
	}
}

// Function for reading in newline delimited list from file
func readList(loc string) (list []string, err error) {
	raw, err := ioutil.ReadFile(loc)
	if err != nil {
		return
	}
	list = strings.Split(string(raw), "\n")
	return
}
