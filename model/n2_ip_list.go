package model

import "fmt"

// N2IPList accepts a single YAML string or a sequence of strings.
type N2IPList []string

// UnmarshalYAML normalizes both forms into a list.
// IP validity and non-empty requirements are checked by configuration validation.
func (ips *N2IPList) UnmarshalYAML(
	unmarshal func(interface{}) error,
) error {
	var value interface{}
	if err := unmarshal(&value); err != nil {
		return err
	}

	var result N2IPList

	switch v := value.(type) {
	case string:
		result = N2IPList{v}

	case []interface{}:
		result = make(N2IPList, len(v))

		for i, item := range v {
			ip, ok := item.(string)
			if !ok {
				return fmt.Errorf(
					"N2 IP list item %d must be a string, got %T",
					i+1, item,
				)
			}
			result[i] = ip
		}

	default:
		return fmt.Errorf(
			"N2 IP must be a string or a list of strings, got %T",
			value,
		)
	}

	*ips = result
	return nil
}
