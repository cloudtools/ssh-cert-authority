package ssh_ca_util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type RequesterConfig struct {
	PublicKeyPath string
	SignerUrl     string
}

type SignerdConfig struct {
	SigningKeyFingerprint string
	AuthorizedSigners     map[string]string
	AuthorizedUsers       map[string]string
	NumberSignersRequired int
}

type SignerConfig struct {
	KeyFingerprint string
	SignerUrl      string
}

func LoadConfig(configPath string, environmentConfigs interface{}) error {
	buf, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	switch configType := environmentConfigs.(type) {
	case *map[string]RequesterConfig, *map[string]SignerConfig, *map[string]SignerdConfig:
		return json.Unmarshal(buf, &environmentConfigs)
	default:
		return fmt.Errorf("oops: %T\n", configType)
	}
}

func GetConfigForEnv(environment string, environmentConfigs interface{}) (interface{}, error) {
	switch environmentConfigs.(type) {
	case *map[string]RequesterConfig:
		configs := *environmentConfigs.(*map[string]RequesterConfig)
		if len(configs) > 1 && environment == "" {
			return nil, fmt.Errorf("You must tell me which environment to use.")
		}
		if len(configs) == 1 && environment == "" {
			for environment = range configs {
				// lame way of extracting first and only key from a map?
			}
		}
		config, ok := configs[environment]
		if !ok {
			return nil, fmt.Errorf("Requested environment not found in config file.")
		}
		return config, nil
	case *map[string]SignerConfig:
		configs := *environmentConfigs.(*map[string]SignerConfig)
		if len(configs) > 1 && environment == "" {
			return nil, fmt.Errorf("You must tell me which environment to use.")
		}
		if len(configs) == 1 && environment == "" {
			for environment = range configs {
				// lame way of extracting first and only key from a map?
			}
		}
		config, ok := configs[environment]
		if !ok {
			return nil, fmt.Errorf("Requested environment not found in config file.")
		}
		return config, nil
	}
	return nil, fmt.Errorf("Programmer error at runtime. I think you passed in a bad config object.")
}
