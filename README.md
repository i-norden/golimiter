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
lim.Rate = 1                                        # rate at which bucket refills
lim.Burst = 6                                       # size of the bucket
lim.Whitelist.On = true                             # turn whitelisting on
lim.Whitelist.Filename = "./whitelist_filename"     # whitelist location
lim.Whitelist.UpdateFreq = 5                        # whitelist read frequency
```

**Initiate the limiter's processes:**

```
err := lim.Init()
```

**And wrap its limit method around your http handler function:**

```
http.ListenAndServe(":443", lim.Limit(http.HandlerFunc(yourHandlerFunc)))
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
