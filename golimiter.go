/* TO DO
Write and perform proper tests
Add ability to preferentialy treat certain vistors/ips (give them better rates)
Add ability to add bad actors to blacklist/remove from whitelist on the go
Refine metric used to define and  measure server load
Handling of X-Forwarded-For or X-Real-IP headers
Reading white/blacklist from dbs
Updating white/blacklist using rpc
*/

package golimiter

import (
	c "github.com/i-norden/golimiter/common"
	"errors"
	"net/http"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Limiter struct { // Whitelist settings
	Rate      rate.Limit      // Default limiter rate
	Burst     int             // Default limiter burst/bucket size
	params    []params        // Limiter params enforced at user defined thresholds
	triggers  []*rate.Limiter // User defined limiters to monitor load and trigger state shift
	Whitelist struct {        // Whitelist settings
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
	visitors   map[string]*visitor // Map to hold the visitor structs for each ip
	useDefault bool                // bool indicating whether or not to use default params
	state      int                 // state variable for the limiter
}

// Class of visitor with limiter settings for default and user defined load conditions
type visitor struct {
	limiter  *rate.Limiter   //limiter used under default conditions
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
Initialization function for exported limiter object
Uses the limiter's internal parameters to initialize
the appropriate background processes
If limiter parameters have been set then it assumes default settings:
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

	l.useDefault = true
	return
}


// Wrap this middleware method around a server's handler struct(s)
// to check each incoming request's IP against their
// limiter, and optionally against an IP whitelist and/or blacklist
func (l *Limiter) LimitHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First update the state of the limiter
		l.updateState()
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
		// the visitor struct with the limiters for the current user.
		visitor := l.getVisitor(r.RemoteAddr)
		// If they have exceeded their limit at the current state, return 429 status
		if !l.allow(visitor) {
			http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
			return
		}
		// If they pass all limits, call the downstream handler function
		next.ServeHTTP(w, r)
	})
}

// Limiter middleware method for a request handler function
func (l *Limiter) LimitHTTPFunc(nextFunc func(http.ResponseWriter, *http.Request)) http.Handler {
	return l.LimitHTTPHandler(http.HandlerFunc(nextFunc))
}

// Limiter middleware method for lower level net connections
// Both the accepted conn and your downstream handler need to be passed
func (l *Limiter) LimitNetConn(conn net.Conn, connHandler func(net.Conn)) {
	// First update the state of the limiter
	l.updateState()
	// Get remote ip from connection
	addr := conn.RemoteAddr()
	ip := addr.String()
	// If whitelist flag is set, check if incoming ip is on whitelist
	if l.Whitelist.On {
		mtx.Lock()
		in, _ := c.InArray(ip, l.Whitelist.list)
		mtx.Unlock()
		// If not on whitelist close the connection and return
		if !in {
			conn.Close()
			return
		}
	}
	// If blacklist flag is set, check if incoming ip is on blacklist
	if l.Blacklist.On {
		mtx.Lock()
		in, _ := c.InArray(ip, l.Blacklist.list)
		mtx.Unlock()
		// If on blacklist close the connection and return
		if in {
			conn.Close()
			return
		}
	}
	// Call the getVisitor method to create or retreive
	// the visitor struct with the limiters for the current user.
	visitor := l.getVisitor(ip)
	// If they have exceeded their limit at the current state,
	// close the connection and return
	if !l.allow(visitor) {
		conn.Close()
		return
	}
	// If they pass all limits, pass the connection to the handler func
	connHandler(conn)
}

// Used to add a new state to the limiter we create a limiter that triggers a
// transition to the defined state when the query rate exceeds the limit rate
// While in this state visitors are limited by a limiter with vRate and vBurst
// When multiple state are triggered the highest order state becomes active
func (l *Limiter) AddState(order int, limit int, vRate rate.Limit, vBurst int) {
	sRate := rate.Limit(limit)
	l.triggers[order] = rate.NewLimiter(sRate, limit)
	l.params[order] = params{rate: vRate, burst: vBurst}
}

// Update state variable based on limiters global limiter states
func (l *Limiter) updateState() {
	mtx.Lock()
	l.useDefault = true
	for i, t := range l.triggers {
		if t.Allow() == false {
			l.state = i
			l.useDefault = false
		}
	}
	mtx.Unlock()
}

// Checks whether or not a visitor (ip) is allowed
// at the current limiter state
func (l *Limiter) allow(v *visitor) bool {
	mtx.Lock()
	defer mtx.Unlock()
	dflt := v.limiter.Allow()
	var levels []bool
	for i, l := range v.limiters { //it needs to iterate and update all of the
		levels[i] = l.Allow() // limiters no matter the current state
	}
	if l.useDefault {
		return dflt
	}
	return levels[l.state]
}

// Check for current visitor's rate limiter and return it if they have one
// If they don't, call the addVisitor function to assign them a new limiter
func (l *Limiter) getVisitor(ip string) *visitor {
	mtx.Lock()
	defer mtx.Unlock()
	v, exists := l.visitors[ip]
	if !exists {
		return l.addVisitor(ip)
	}
	// Update the last seen time for the visitor.
	v.lastSeen = time.Now()
	return v
}

// Creates a new limiter and adds it to the visitors map
// with the user's IP address as the key.
func (l *Limiter) addVisitor(ip string) (v *visitor) {
	mtx.Lock()
	v.limiter = rate.NewLimiter(l.Rate, l.Burst)
	for i, p := range l.params {
		v.limiters[i] = rate.NewLimiter(p.rate, p.burst)
	}
	v.lastSeen = time.Now()
	l.visitors[ip] = v
	mtx.Unlock()
	return
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
			return
		default:
			newList, err := c.ReadList(l.Whitelist.Filename)
			if err == nil {
				mtx.Lock()
				l.Whitelist.list = newList
				mtx.Unlock()
			}
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
			newList, err := c.ReadList(l.Blacklist.Filename)
			if err == nil {
				mtx.Lock()
				l.Blacklist.list = newList
				mtx.Unlock()
			}
			time.Sleep(time.Minute * l.Blacklist.UpdateFreq)
		}
	}
}
