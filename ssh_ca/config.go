package ssh_ca

import (
	"encoding/json"
	"os"
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

func read_config_file(config_path string) ([]byte, error) {
	file, err := os.Open(config_path)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 1<<16)
	count, err := file.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[0:count], nil
}

func LoadRequesterConfig(config_path string) (map[string]RequesterConfig, error) {
	environment_configs := make(map[string]RequesterConfig)

	raw_config, err := read_config_file(config_path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(raw_config, &environment_configs)
	if err != nil {
		return nil, err
	}

	return environment_configs, nil
}

func LoadSignerdConfig(config_path string) (map[string]SignerdConfig, error) {
	environment_configs := make(map[string]SignerdConfig)

	raw_config, err := read_config_file(config_path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(raw_config, &environment_configs)
	if err != nil {
		return nil, err
	}

	return environment_configs, nil

}

func LoadSignerConfig(config_path string) (map[string]SignerConfig, error) {
	environment_configs := make(map[string]SignerConfig)

	raw_config, err := read_config_file(config_path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(raw_config, &environment_configs)
	if err != nil {
		return nil, err
	}

	return environment_configs, nil

}
