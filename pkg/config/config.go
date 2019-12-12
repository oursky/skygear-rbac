package config

import "os"

// Config is the config for this application
type Config struct {
	Model     string
	File      string
	Database  string
	TableName string
	SentryDsn string
}

// LoadFromEnv loads value from env or return default value if missing
func LoadFromEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// LoadConfigFromEnv loads config from env
func LoadConfigFromEnv() Config {
	if LoadFromEnv("ENV", "") == "development" {
		return Config{
			Model: "./model.conf",
			File:  "./policy.csv",
		}
	}
	return Config{
		Model:     "./model.conf",
		Database:  LoadFromEnv("DATABASE_URL", ""),
		File:      LoadFromEnv("POLICY_PATH", ""),
		TableName: LoadFromEnv("TABLE_NAME", "casbin_rule"),
		SentryDsn: LoadFromEnv("SENTRY_DSN", ""),
	}
}
