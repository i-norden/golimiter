package limiter

import (
	"net/http"
	"time"
  "sync"
  "strings"
  "io/ioutil"

  "golang.org/x/time/rate"
)

// Create a custom visitor struct which holds the rate limiter for each
// visitor and the last time that the visitor was seen.
type visitor struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}

// Create a map to hold the visitor structs for each ip
var visitors = make(map[string]*visitor)

// Mutex for locking access to shared data structs
var mtx sync.Mutex

// Create whitelist to hold allowed ip addresses
var whitelist = make([]string, 0)

// Function to update whitelist to allow user access
func UpdateWhitelist(loc string) {
  for {
      mtx.Lock()
      newList, err := readWhitelist(loc)
      if err == nil {
        whitelist = newList
      }
      mtx.Unlock()
      time.Sleep(time.Minute*5)
  }
}

// Function for reading in whitelist
func readWhitelist(loc string) (list []string, err error) {
	raw, err := ioutil.ReadFile(loc)
	if err != nil {
		return
	}
  list = strings.Split(string(raw), "\r\n")
	return
}

// Create a new rate limiter and add it to the visitors map, using the
// IP address as the key.
func addVisitor(ip string) *rate.Limiter {
    // Create a token bucket limiter that allows 1 query/second or burst of 6
    limiter := rate.NewLimiter(1, 6)
    mtx.Lock()
    // Include the current time when creating a new visitor.
    visitors[ip] = &visitor{limiter, time.Now()}
    mtx.Unlock()
    return limiter
}

// Retrieve and return the rate limiter for the current visitor if it
// already exists. Otherwise call the addVisitor function to add a
// new entry to the map.
func getVisitor(ip string) *rate.Limiter {
    mtx.Lock()
    v, exists := visitors[ip]
    if !exists {
        mtx.Unlock()
        return addVisitor(ip)
    }
    // Update the last seen time for the visitor.
    v.lastSeen = time.Now()
    mtx.Unlock()
    return v.limiter
}

// Every minute check the map for visitors that haven't been seen for
// more than 3 minutes and delete the entries.
func CleanupVisitors() {
    for {
        time.Sleep(time.Minute)
        mtx.Lock()
        for ip, v := range visitors {
            if time.Now().Sub(v.lastSeen) > 3*time.Minute {
                delete(visitors, ip)
            }
        }
        mtx.Unlock()
    }
}

// Checks incoming ip against their limiter
func Limit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check if incoming ip is on whitelist
        mtx.Lock()
        in, _ := InArray(r.RemoteAddr, whitelist)
        mtx.Unlock()
        // If not return 401 status
        if !in {
          http.Error(w, http.StatusText(401), http.StatusUnauthorized)
          return
        }
        // Call the getVisitor function to retreive the rate limiter for
        // the current user.
        limiter := getVisitor(r.RemoteAddr)
        // If they have exceeded their limit, return 429 status
        if limiter.Allow() == false {
            http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// Common function to check if string is in array
func InArray(val string, array []string) (exists bool, index int) {
	exists = false
	for i, v := range array {
		if val == v {
			return true, i
		}
	}
	return
}
