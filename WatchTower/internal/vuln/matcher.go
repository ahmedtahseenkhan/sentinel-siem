package vuln

import (
	"strconv"
	"strings"
)

func CompareVersions(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var numA, numB int
		if i < len(partsA) {
			numA, _ = strconv.Atoi(strings.TrimLeft(partsA[i], "0"))
		}
		if i < len(partsB) {
			numB, _ = strconv.Atoi(strings.TrimLeft(partsB[i], "0"))
		}
		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
	}
	return 0
}
