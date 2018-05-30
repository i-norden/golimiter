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

lim := httplimiter.Limiter
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

**And wrap it's limit method around your http handler function:**

```
http.ListenAndServe(":8080", lim.Limit(http.HandlerFunc(yourHandlerFunc)))
```

Note that white/blacklist files currently need to be in the form <br />
of a newline ("\n") delimitated list of the IP address strings

## License

MIT © [Ian Norden]
