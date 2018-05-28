# httplimiter

WORK IN PROGRESS

## Install

go get github.com/i-norden/httplimiter

## Usage

###Don't use it yet, it's not ready!

import "github.com/i-norden/httplimiter"

####In main, instantiate a new limiter object and set desired parameters:

lim := httplimiter.Limiter
lim.Whitelist.On = true
lim.Whitelist.Filename = "./whitelist_filename"
lim.Whitelist.UpdateFreq = 5

####Initiate the limiter's processes:

err := lim.Init()

####And wrap it around your http handler function

http.ListenAndServe(":8080", lim.Limit(http.HandlerFunc(yourCustomHandlerFunc)))

## License

MIT © [Ian Norden]
