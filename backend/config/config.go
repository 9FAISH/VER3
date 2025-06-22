package config

type Config struct {
	ServerPort string
	// TODO: Add fields for DB, LLM service, update URLs, etc.
}

func LoadConfig() (*Config, error) {
	// NOTE: This is a stub. In production, load config from file or environment variables.
	return &Config{ServerPort: ":8080"}, nil
}
