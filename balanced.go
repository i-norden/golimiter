/* TO DO
Finish current state of things
Add ability to blacklist bad actors (those that abuse api limit or otherwise)
Enable custom number of threshold/limits
Refine metric used to define and  measure server load
*/

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
type balancer struct { // Whitelist settings
	Limits struct { // Limiter conditions enforced for visitors at each if the server load states
		Low struct { // Limiter params used during "normal" load (aka load that doesn't surpass med or high thresholds)
			Rate  rate.Limit
			Burst int
		}
		Med struct { // Limiter params used during medium load
			Rate  rate.Limit
			Burst int
		}
		High struct { // Limiter params used during high load
			Rate  rate.Limit
			Burst int
		}
	}
	triggers struct { // Limiters used to trigger load state shift (defualt is low)
		med  *rate.Limiter // Exhausting this limiter will set server load state to medium
		high *rate.Limiter // Exhausting this limiter will set server load state to high
	}
	Whitelist struct { // Whitelist settings
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
	CleanUp struct { // Background cleanup process settings
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

// State variale to represent server load
var load state

/*
Used to create and return a new balancer

suppose you have a server that can support 10k users each at an
api limit of 1/second w/ bursts up to 6. Thats an expected load of
10,000/second w/burst up to 60,000/second.
If suddenly the number of users surges, in an attempt to maintain the same
overall load we can cut the visitors' allowed rates and bursts accordingly

E.g. to respond to a 2x or 10x increase in demand
we can acheive this by creating a balancer with a "med" limiter at
a rate 10,000 and buckset size of 60,000, and a "high" limiter at
a rate of 100,000 and size of 600,000. Every incoming api request handled
by the balancer drains from these limiters, and exhausting their buckets
causes the visitors to switch which limiter they use
(from the default "low" one to the "med" or "high" one) which are defined
during ... (still need to write that func)
*/
func NewBalancer(medRate, highRate rate.Limit, medBktSize, lrgBktSize int) *balancer {
	var bal balancer
	bal.triggers.med = rate.NewLimiter(medRate, medBktSize)
	bal.triggers.high = rate.NewLimiter(highRate, lrgBktSize)
	return &bal
}

// Update state variable based on balancers global limiter states
func (b *balancer) update() {
	mtx.Lock()
	load.set("low")
	if b.triggers.med.Allow() == false {
		load.set("med")
	}
	if b.triggers.high.Allow() == false {
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
