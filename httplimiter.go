/* TO DO:
Adjust limits based on server load (internal balancer)
Handling of X-Forwarded-For or X-Real-IP headers
Reading white/blacklist from dbs
Updating white/blacklist using rpc
*/
package httplimiter

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Struct which holds the rate limiter for each
// visitor and the last time that the visitor was seen.
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
	CleanUp struct { // Background cleanup process settings
		Off      bool          // On or off (default false- on)
		Thres    time.Duration // Time before visitor expires and is removed (in minutes)
		Freq     time.Duration // Cleanup frequency (in minutes)
		quitChan chan bool     // Channel used to stop the background goroutine
	}
	visitors map[string]*visitor //Map to hold the visitor structs for each ip
}

// Mutex for locking access to shared data structs
var mtx sync.Mutex

// Function to update whitelist from a file
func (l *Limiter) updateWhitelist(quit chan bool) {
	for {
		select {
		case <-quit:
			return
		default:
			mtx.Lock()
			newList, err := readList(l.Whitelist.Filename)
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
			return
		default:
			mtx.Lock()
			newList, err := readList(l.Blacklist.Filename)
			if err == nil {
				l.Blacklist.list = newList
			}
			mtx.Unlock()
			time.Sleep(time.Minute * l.Blacklist.UpdateFreq)
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

/*
Initialization function for exported limiter object
Uses the limiter's internal parameters to initialize
the appropriate background processes
If no limiter parameters have not been set then it assumes default settings:
  - Whitelist and blacklist turned off
  - CleanUp turned on at a freq and thres of 3 minutes
  - Rate of 1 per second
  - Bucket size (max burst) of 5
*/
func (l *Limiter) Init() (err error) {
	mtx.Lock()
	defer mtx.Unlock()
	if l.Whitelist.On {
		if l.Whitelist.Filename == "" {
			err = errors.New("Whitelist configuration file path is not set")
			return
		}
		_, err = readList(l.Whitelist.Filename)
		if err != nil {
			return
		}
		if l.Whitelist.UpdateFreq == 0 {
			l.Whitelist.UpdateFreq = 3
		}
		var qWL chan bool
		go l.updateWhitelist(qWL)
		l.Whitelist.quitChan = qWL
	}
	if l.Blacklist.On {
		if l.Blacklist.Filename == "" {
			l.Whitelist.quitChan <- true
			return errors.New("Blacklist configuration file path is not set")
		}
		_, err = readList(l.Blacklist.Filename)
		if err != nil {
			l.Whitelist.quitChan <- true
			return
		}
		if l.Blacklist.UpdateFreq == 0 {
			l.Blacklist.UpdateFreq = 3
		}
		var qBL chan bool
		go l.updateBlacklist(qBL)
		l.Blacklist.quitChan = qBL
	}
	if !l.CleanUp.Off {
		if l.CleanUp.Freq == 0 {
			l.CleanUp.Freq = 3
		}
		if l.CleanUp.Thres == 0 {
			l.CleanUp.Thres = 3
		}
		var qCU chan bool
		go l.cleanupVisitors(qCU)
		l.CleanUp.quitChan = qCU
	}
	if l.Rate == 0 {
		l.Rate = 1
	}
	if l.Burst == 0 {
		l.Burst = 5
	}
	if l.visitors == nil {
		l.visitors = make(map[string]*visitor)
	}
	return
}

// Check for current visitor's rate limiter and return it if they have one
// If they don't, call the addVisitor function to assign them a new limiter
func (l *Limiter) getVisitor(ip string) *rate.Limiter {
	mtx.Lock()
	v, exists := l.visitors[ip]
	if !exists {
		mtx.Unlock()
		return l.addVisitor(ip)
	}
	// Update the last seen time for the visitor.
	v.lastSeen = time.Now()
	mtx.Unlock()
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
			time.Sleep(l.CleanUp.Freq * time.Minute)
			mtx.Lock()
			for ip, v := range l.visitors {
				if time.Now().Sub(v.lastSeen) > l.CleanUp.Thres*time.Minute {
					delete(l.visitors, ip)
				}
			}
			mtx.Unlock()
		}
	}
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
			in, _ := inArray(r.RemoteAddr, l.Whitelist.list)
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
			in, _ := inArray(r.RemoteAddr, l.Blacklist.list)
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

// Common function to check if string is in array
func inArray(val string, array []string) (exists bool, index int) {
	exists = false
	for i, v := range array {
		if val == v {
			return true, i
		}
	}
	return
}
