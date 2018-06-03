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
