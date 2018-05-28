package httplimiter

import (
  funcs "../funcs"
	"net/http"
	"time"
  "sync"

  "golang.org/x/time/rate"
)

// Create a custom visitor struct which holds the rate limiter for each
// visitor and the last time that the visitor was seen.
type visitor struct {
    Limiter  *rate.Limiter
    lastSeen time.Time
}

// Initialize a limiter object from the imported rate module
// In this case 1 call is allowed per second with bursts of up to 6 per second
var limiter = rate.NewLimiter(1, 6)

// Create a map to hold the visitor structs for each ip
var visitors = make(map[string]*visitor)
var mtx sync.Mutex

// Create whitelist to hold allowed ip addresses
var whitelist = make([]string, 0)

// Function to update whitelist to allow user access
func UpdateWhitelist(ip string) {
  in, _ := funcs.InArray(ip, whitelist)
  if !in {
    whitelist = append(whitelist, ip)
  }
  return
}

// Create a new rate limiter and add it to the visitors map, using the
// IP address as the key.
func addVisitor(ip string) *rate.Limiter {
    limiter := rate.NewLimiter(2, 5)
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
    return v.Limiter
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

//checks incoming ip against their limit
func Limit(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Call the getVisitor function to retreive the rate limiter for
        // the current user.
        in, _ := funcs.InArray(r.RemoteAddr, whitelist)
        if !in {
          http.Error(w, http.StatusText(401), http.StatusUnauthorized)
          return
        }
        limiter := getVisitor(r.RemoteAddr)
        if limiter.Allow() == false {
            http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}
