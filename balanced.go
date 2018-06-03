/* TO DO
Write and perform proper tests
Add ability to add bad actors to blacklist/remove from whitelist on the go
Refine metric used to define and  measure server load
Handling of X-Forwarded-For or X-Real-IP headers
Reading white/blacklist from dbs
Updating white/blacklist using rpc
*/

package httplimiter

import (
	c "./common"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Structs for internal load balancing
// that adjusts api limits according to overall demand
// Balancer is used to rate the server's aggregated load
type Balancer struct { // Whitelist settings
	Rate      rate.Limit               // Default limiter rate
	Burst     int                      // Default limiter burst/bucket size
	params    []params        // Limiter params enforced at user defined thresholds
	triggers  []*rate.Limiter // User defined limiters to monitor load and trigger state shift
	Whitelist struct {                 // Whitelist settings
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
	Cleanup struct { // Background cleanup process settings
		Off      bool          // On or off (default false- on)
		Thres    time.Duration // Time before visitor expires and is removed (in minutes)
		Freq     time.Duration // Cleanup frequency (in minutes)
		quitChan chan bool     // Channel used to stop the background goroutine
	}
	visitors map[string]*visitor // Map to hold the visitor structs for each ip
	useDefault bool										// bool indicating whether or not to use default params
	state    int              // state variable for the balancer
}

// Class of visitor with limiter settings for default and user defined load conditions
type visitor struct {
	limiter  *rate.Limiter            //limiter use under default conditions
	limiters []*rate.Limiter //limiters used under variable load conditions
	lastSeen time.Time
}

// Params for a rate.Limiter
type params struct {
	rate  rate.Limit
	burst int
}

// Mutex for locking access to shared data structs
var mtx sync.Mutex

/*
Initialization function for exported balancer object
Uses the limiter's internal parameters to initialize
the appropriate background processes
If limiter parameters have been set then it assumes default settings:
  - Whitelist and blacklist turned off
  - Cleanup turned on at a freq and thres of 3 minutes
  - Rate of 1 per second
  - Bucket size (max burst) of 5
*/
func (b *Balancer) Init() (err error) {
	mtx.Lock()
	defer mtx.Unlock()
	if b.Whitelist.On { // If using whitelist, read in list and initialize update process
		if b.Whitelist.Filename == "" { // Return error if no file path is given
			err = errors.New("Whitelist configuration file path is not set")
			return
		}
		_, err = c.ReadList(b.Whitelist.Filename)
		if err != nil { // Return error if list can't be read in
			return
		}
		if b.Whitelist.UpdateFreq == 0 {
			b.Whitelist.UpdateFreq = 3 // Use default freq if none provided
		}
		var qWL chan bool
		go b.updateWhitelist(qWL)
		b.Whitelist.quitChan = qWL
	}

	if b.Blacklist.On { // If using blacklist, read in list and initialize update process
		if b.Blacklist.Filename == "" { // Return error if no file path is given
			if b.Whitelist.On {
				b.Whitelist.On = false
				b.Whitelist.quitChan <- true // and shut down whitelist process if it exists
			}
			return errors.New("Blacklist configuration file path is not set")
		}
		_, err = c.ReadList(b.Blacklist.Filename)
		if err != nil { // Return error if list can't be read in
			if b.Whitelist.On {
				b.Whitelist.On = false
				b.Whitelist.quitChan <- true // and shut down whitelist process if it exists
			}
			return
		}
		if b.Blacklist.UpdateFreq == 0 {
			b.Blacklist.UpdateFreq = 3 // Use default freq if none provided
		}
		var qBL chan bool
		go b.updateBlacklist(qBL)
		b.Blacklist.quitChan = qBL
	}

	if !b.Cleanup.Off { // Visitor cleanup is on by default
		if b.Cleanup.Freq == 0 {
			b.Cleanup.Freq = 3 // Use default freq if none provided
		}
		if b.Cleanup.Thres == 0 {
			b.Cleanup.Thres = 3 // Use default thres if none provided
		}
		var qCU chan bool
		go b.cleanupVisitors(qCU)
		b.Cleanup.quitChan = qCU
	}

	if b.Rate == 0 {
		b.Rate = 1 // Use default rate if none provided
	}

	if b.Burst == 0 {
		b.Burst = 5 // Use default burst if none provided
	}

	if b.visitors == nil { // Initialize visitors map if none exists
		b.visitors = make(map[string]*visitor)
	}

	b.useDefault = true
	return
}

/*
Wrap this method around a server's handler function(s)
to check each incoming request's IP against their
limiter, and optionally against an IP whitelist and/or blacklist
*/
func (b *Balancer) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First update the state of the balancer
		b.updateState()
		// If whitelist flag is set, check if incoming ip is on whitelist
		if b.Whitelist.On {
			mtx.Lock()
			in, _ := c.InArray(r.RemoteAddr, b.Whitelist.list)
			mtx.Unlock()
			// If not on whitelist return 401 status
			if !in {
				http.Error(w, http.StatusText(401), http.StatusUnauthorized)
				return
			}
		}
		// If blacklist flag is set, check if incoming ip is on blacklist
		if b.Blacklist.On {
			mtx.Lock()
			in, _ := c.InArray(r.RemoteAddr, b.Blacklist.list)
			mtx.Unlock()
			// If on blacklist return 401 status
			if in {
				http.Error(w, http.StatusText(401), http.StatusUnauthorized)
				return
			}
		}
		// Call the getVisitor method to create or retreive
		// the rate visitor struct with the limiters for the current user.
		visitor := b.getVisitor(r.RemoteAddr)
		// If they have exceeded their limit at the current state, return 429 status
		if !b.allow(visitor) {
			http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

/*
Used to add a new state to the balancer
sRate and sBurst are used to create a trigger limiter whose depletion triggers
a transition to the defined state, while in this state visitors are limited
by a limiter with vRate and vBurst
The order indicates the position of this state relative to the others,
when multiple state are triggered the highest order state becomes the active one
*/
func (b *Balancer) AddState(order int, sRate rate.Limit, sBurst int, vRate rate.Limit, vBurst int) {
	b.triggers[order] = rate.NewLimiter(sRate, sBurst)
	b.params[order] = params{rate: vRate, burst: vBurst}
}

// Update state variable based on balancers global limiter states
func (b *Balancer) updateState() {
	mtx.Lock()
	b.useDefault = true
	for i, t := range b.triggers {
		if t.Allow() == false {
			b.state = i
			b.useDefault = false
		}
	}
	mtx.Unlock()
}

// Checks whether or not a visitor (ip) is allowed
// at the current balancer state
func (b *Balancer) allow(v *visitor) bool {
	mtx.Lock()
	defer mtx.Unlock()
	dflt := v.limiter.Allow()
	var levels []bool
	for i, l := range v.limiters { //it needs to iterate and update all of the
		levels[i] = l.Allow() // limiters no matter the current state
	}
	if b.useDefault {
		return dflt
	}
	return levels[b.state]
}

// Check for current visitor's rate limiter and return it if they have one
// If they don't, call the addVisitor function to assign them a new limiter
func (b *Balancer) getVisitor(ip string) *visitor {
	mtx.Lock()
	defer mtx.Unlock()
	v, exists := b.visitors[ip]
	if !exists {
		return b.addVisitor(ip)
	}
	// Update the last seen time for the visitor.
	v.lastSeen = time.Now()
	return v
}

// Creates a new limiter and adds it to the visitors map
// with the user's IP address as the key.
func (b *Balancer) addVisitor(ip string) (v *visitor) {
	mtx.Lock()
	v.limiter = rate.NewLimiter(b.Rate, b.Burst)
	for i, p := range b.params {
		v.limiters[i] = rate.NewLimiter(p.rate, p.burst)
	}
	v.lastSeen = time.Now()
	b.visitors[ip] = v
	mtx.Unlock()
	return
}

// Every minute check the map for visitors that haven't been
// seen for more than x minutes and remove them.
func (b *Balancer) cleanupVisitors(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			time.Sleep(b.Cleanup.Freq * time.Minute)
			mtx.Lock()
			for ip, v := range b.visitors {
				if time.Now().Sub(v.lastSeen) > b.Cleanup.Thres*time.Minute {
					delete(b.visitors, ip)
				}
			}
			mtx.Unlock()
		}
	}
}

// Function to update whitelist from a file
func (b *Balancer) updateWhitelist(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			mtx.Lock()
			newList, err := c.ReadList(b.Whitelist.Filename)
			if err == nil {
				b.Whitelist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * b.Whitelist.UpdateFreq)
		}
	}
}

// Function to update blacklist from a file
func (b *Balancer) updateBlacklist(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			mtx.Lock()
			newList, err := c.ReadList(b.Blacklist.Filename)
			if err == nil {
				b.Blacklist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * b.Blacklist.UpdateFreq)
		}
	}
}
