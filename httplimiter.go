/* TO DO:
Add ability to blacklist bad actors (those that abuse api limit or otherwise)
Adjust limits based on server load (internal balancer)
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

// Struct which holds the rate limiter for each
// visitor and the last time that the visitor was seen
type visitor struct {
	limiter  *rate.Limiter // Leaky-bucket limiter object
	lastSeen time.Time     // So that we know when to cleanup visitor
}

// Struct to represent the IP limiter with control paramters
type Limiter struct {
	Rate      rate.Limit
	Burst     int
	Whitelist struct { // Whitelist settings
		On         bool          // On or off (default false- off)
		Filename   string        // File location
		UpdateFreq time.Duration // Update frequency (how often it reads file to check for changes; in minutes)
		quitChan   chan bool     // Channel used to stop the background goroutine
		list       []string      // The whitelist as an array of allowed ip addresses
	}
	Blacklist struct { // Blacklist settings
		On         bool          // On or off (default false- off)
		Filename   string        // File location
		UpdateFreq time.Duration // Update frequency (in minutes)
		quitChan   chan bool     // Channel used to stop the background goroutine
		list       []string      // The blacklist as an array of disallowed ip address
	}
	Cleanup struct { // Background cleanup process settings
		Off      bool          // On or off (default false- on)
		Thres    time.Duration // Time before visitor expires and is removed (in minutes)
		Freq     time.Duration // Cleanup frequency (in minutes)
		quitChan chan bool     // Channel used to stop the background goroutine
	}
	visitors map[string]*visitor //Map to hold the visitor structs for each ip
}

// Mutex for locking access to shared data structs
var mtx sync.Mutex

/*
Initialization function for exported limiter object
Uses the limiter's internal parameters to initialize
the appropriate background processes
If  limiter parameters have not been set then it assumes default settings:
  - Whitelist and blacklist turned off
  - Cleanup turned on at a freq and thres of 3 minutes
  - Rate of 1 per second
  - Bucket size (max burst) of 5
*/
func (l *Limiter) Init() (err error) {
	mtx.Lock()
	defer mtx.Unlock()
	if l.Whitelist.On { // If using whitelist, read in list and initialize update process
		if l.Whitelist.Filename == "" { // Return error if no file path is given
			err = errors.New("Whitelist configuration file path is not set")
			return
		}
		_, err = c.ReadList(l.Whitelist.Filename)
		if err != nil { // Return error if list can't be read in
			return
		}
		if l.Whitelist.UpdateFreq == 0 {
			l.Whitelist.UpdateFreq = 3 // Use default freq if none provided
		}
		var qWL chan bool
		go l.updateWhitelist(qWL)
		l.Whitelist.quitChan = qWL
	}

	if l.Blacklist.On { // If using blacklist, read in list and initialize update process
		if l.Blacklist.Filename == "" { // Return error if no file path is given
			if l.Whitelist.On {
				l.Whitelist.On = false
				l.Whitelist.quitChan <- true // and shut down whitelist process if it exists
			}
			return errors.New("Blacklist configuration file path is not set")
		}
		_, err = c.ReadList(l.Blacklist.Filename)
		if err != nil { // Return error if list can't be read in
			if l.Whitelist.On {
				l.Whitelist.On = false
				l.Whitelist.quitChan <- true // and shut down whitelist process if it exists
			}
			return
		}
		if l.Blacklist.UpdateFreq == 0 {
			l.Blacklist.UpdateFreq = 3 // Use default freq if none provided
		}
		var qBL chan bool
		go l.updateBlacklist(qBL)
		l.Blacklist.quitChan = qBL
	}

	if !l.Cleanup.Off { // Visitor cleanup is on by default
		if l.Cleanup.Freq == 0 {
			l.Cleanup.Freq = 3 // Use default freq if none provided
		}
		if l.Cleanup.Thres == 0 {
			l.Cleanup.Thres = 3 // Use default thres if none provided
		}
		var qCU chan bool
		go l.cleanupVisitors(qCU)
		l.Cleanup.quitChan = qCU
	}

	if l.Rate == 0 {
		l.Rate = 1 // Use default rate if none provided
	}

	if l.Burst == 0 {
		l.Burst = 5 // Use default burst if none provided
	}

	if l.visitors == nil { // Initialize visitors map if none exists
		l.visitors = make(map[string]*visitor)
	}
	return
}

/*
Wrap this method around a server's handler function(s)
to check each incoming request's IP against their
limiter, and optionally against an IP whitelist and/or blacklist
*/
func (l *Limiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If whitelist flag is set, check if incoming ip is on whitelist
		if l.Whitelist.On {
			mtx.Lock()
			in, _ := c.InArray(r.RemoteAddr, l.Whitelist.list)
			mtx.Unlock()
			// If not on whitelist return 401 status
			if !in {
				http.Error(w, http.StatusText(401), http.StatusUnauthorized)
				return
			}
		}
		// If blacklist flag is set, check if incoming ip is on blacklist
		if l.Blacklist.On {
			mtx.Lock()
			in, _ := c.InArray(r.RemoteAddr, l.Blacklist.list)
			mtx.Unlock()
			// If on blacklist return 401 status
			if in {
				http.Error(w, http.StatusText(401), http.StatusUnauthorized)
				return
			}
		}
		// Call the getVisitor method to create or retreive
		// the rate limiter for the current user.
		user := l.getVisitor(r.RemoteAddr)
		// If they have exceeded their limit, return 429 status
		if user.Allow() == false {
			http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Check for current visitor's rate limiter and return it if they have one
// If they don't, call the addVisitor function to assign them a new limiter
func (l *Limiter) getVisitor(ip string) *rate.Limiter {
	mtx.Lock()
	defer mtx.Unlock()
	v, exists := l.visitors[ip]
	if !exists {
		return l.addVisitor(ip)
	}
	// Update the last seen time for the visitor.
	v.lastSeen = time.Now()
	return v.limiter
}

// Creates a new limiter and adds it to the visitors map
// with the user's IP address as the key.
func (l *Limiter) addVisitor(ip string) *rate.Limiter {
	// Create a token bucket limiter that allows base querys/second or burst amount at once
	limiter := rate.NewLimiter(l.Rate, l.Burst)
	mtx.Lock()
	l.visitors[ip] = &visitor{limiter, time.Now()}
	mtx.Unlock()
	return limiter
}

// Every minute check the map for visitors that haven't been
// seen for more than x minutes and remove them.
func (l *Limiter) cleanupVisitors(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			time.Sleep(l.Cleanup.Freq * time.Minute)
			mtx.Lock()
			for ip, v := range l.visitors {
				if time.Now().Sub(v.lastSeen) > l.Cleanup.Thres*time.Minute {
					delete(l.visitors, ip)
				}
			}
			mtx.Unlock()
		}
	}
}

// Function to update whitelist from a file
func (l *Limiter) updateWhitelist(quit chan bool) {
	for {
		select {
		case <-quit:
			l.Whitelist.On = false
			return
		default:
			mtx.Lock()
			newList, err := c.ReadList(l.Whitelist.Filename)
			if err == nil {
				l.Whitelist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * l.Whitelist.UpdateFreq)
		}
	}
}

// Function to update blacklist from a file
func (l *Limiter) updateBlacklist(quit chan bool) {
	for {
		select {
		case <-quit:
			l.Blacklist.On = false
			return
		default:
			mtx.Lock()
			newList, err := c.ReadList(l.Blacklist.Filename)
			if err == nil {
				l.Blacklist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * l.Blacklist.UpdateFreq)
		}
	}
}
