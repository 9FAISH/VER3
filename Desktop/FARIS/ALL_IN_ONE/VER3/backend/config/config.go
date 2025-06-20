package config

type Config struct {
	ServerPort string
	// TODO: Add fields for DB, LLM service, update URLs, etc.
}

func LoadConfig() (*Config, error) {
	// TODO: Load config from file or environment
	return &Config{ServerPort: ":8080"}, nil
}
