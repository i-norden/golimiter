# httplimiter

WORK IN PROGRESS

## Install

go get github.com/i-norden/httplimiter

## Usage

```
import "github.com/i-norden/httplimiter"
```

**Instantiate a new limiter object and set desired parameters:**
```
# The below creates a limiter that applies a whitelist and allows permitted
# users 1 api call per second with burst up to 6 per second

lim := httplimiter.Limiter{}
lim.Rate = 5                                        # rate at which bucket refills
lim.Burst = 15                                      # size of the bucket
lim.Whitelist.On = true                             # turn whitelisting on
lim.Whitelist.Filename = "./whitelist_filename"     # whitelist location
lim.Whitelist.UpdateFreq = 5                        # whitelist read frequency
```

**Initiate the limiter's processes:**

```
err := lim.Init()
```

**And wrap its LimitHandler method around an http.Handler:**

```
http.ListenAndServe(":443", lim.LimitHandler(http.HandlerFunc(yourHandlerFunc)))
```

**Or its LimitFunc method around around a handler function:**

```
http.ListenAndServe(":443", lim.LimitFunc(yourHandlerFunc))
```

**Experimental feature**
**Add universal request thresholds to the limiter and define new rate**
**restrictions to enforce when they are surpassed in attempt to balance load**

```
# The below adds a load threshold to the limiter of 5000 per second by
# creating a leaky bucket with a size of 5000 that refills at a rate of 5000
# per second and is drained by all incoming requests handled by the limiter
# When this shared bucket is depleted it causes incoming requests to be
# limited using new, lower rate and burst sizes (0.5 and 3 instead of 1 and 6)

lim.AddState(0, 5000, 3, 10)

# You can add as many states as you like, but be sure to specify
# their ordering using the first (int) argument to the AddState
# method when multiple thresholds are simultaneously surpassed
# the highest order state becomes the active one

lim.AddState(1, 10000, 1, 5)
lim.AddState(2, 20000, 0.5, 2)
```

Note that white/blacklist files currently need to be in the form <br />
of a newline ("\n") delimitated list of the IP address strings

Also note that the white/blacklists and the list of visitors with their
associated limiters are internal to a limiter so two distinct
limiter objects will enforce their own limitations completely independent of
one another. You can reuse the same limiter on different handler functions
if you want to enforce shared api limitations across all of them or instantiate
different limiters to impose separate limitations on each handler

## License

MIT © [Ian Norden]
