package config

import "os"

// LoadFromEnv loads value from env or return default value if missing
func LoadFromEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
