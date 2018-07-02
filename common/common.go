package common

import (
	"io/ioutil"
	"strings"
)

// Function for reading in newline delimited list from file
func ReadList(loc string) (list []string, err error) {
	raw, err := ioutil.ReadFile(loc)
	if err != nil {
		return
	}
	list = strings.Split(string(raw), "\n")
	return
}

// Common function to check if string is in array and return it's index
// If there are duplicates it returns the first found (lowest index)
func InArray(array []string, val string) (exists bool, index int) {
	exists = false
	for i, v := range array {
		if val == v {
			return true, i
		}
	}
	return
}
