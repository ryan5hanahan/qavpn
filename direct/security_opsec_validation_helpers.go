package direct

import (
	"crypto/subtle"
	"time"
)

// Helper functions for security validation tests

// constantTimeCompare performs constant-time comparison of byte slices
func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// calculateMeanDuration calculates the mean of a slice of durations
func calculateMeanDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

// calculateVarianceDuration calculates the variance of a slice of durations
func calculateVarianceDuration(durations []time.Duration, mean time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var sumSquaredDiffs time.Duration
	for _, d := range durations {
		diff := d - mean
		if diff < 0 {
			diff = -diff
		}
		sumSquaredDiffs += diff * diff / time.Duration(len(durations))
	}
	
	// Return approximate square root
	return time.Duration(int64(sumSquaredDiffs) / int64(len(durations)))
}

// isLowEntropy checks if data has low entropy (potentially weak encryption)
func isLowEntropy(data []byte) bool {
	if len(data) < 32 {
		return true // Too small to have good entropy
	}
	
	// Count unique bytes
	byteCount := make(map[byte]int)
	for _, b := range data {
		byteCount[b]++
	}
	
	// If less than 50% unique bytes, consider low entropy
	uniqueBytes := len(byteCount)
	threshold := len(data) / 2
	
	return uniqueBytes < threshold
}
