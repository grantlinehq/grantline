package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

var gitRevision = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

func validateJobAttribute(key string, raw json.RawMessage) error {
	invalid := fmt.Errorf("attribute %q has an unsupported shape", key)
	switch key {
	case "job_kind":
		var value string
		if json.Unmarshal(raw, &value) != nil || (value != "job" && value != "folder") {
			return invalid
		}
	case "jenkinsfile_commit":
		var value string
		if json.Unmarshal(raw, &value) != nil || !gitRevision.MatchString(value) {
			return invalid
		}
	case "buildable":
		var value *bool
		if json.Unmarshal(raw, &value) != nil || value == nil {
			return invalid
		}
	case "credential_reference_count":
		var value *int
		if json.Unmarshal(raw, &value) != nil || value == nil || *value < 0 {
			return invalid
		}
	case "builds":
		var values []struct {
			Number    *int64  `json:"number"`
			Result    *string `json:"result"`
			Building  *bool   `json:"building"`
			Timestamp *int64  `json:"timestamp"`
			Duration  *int64  `json:"duration"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&values) != nil || ensureSingleJSONValue(decoder) != nil || values == nil || len(values) > 20 {
			return invalid
		}
		seen := map[int64]bool{}
		for _, value := range values {
			if value.Number == nil || *value.Number < 1 || seen[*value.Number] || value.Building == nil || value.Timestamp == nil || *value.Timestamp < 0 || value.Duration == nil || *value.Duration < 0 {
				return invalid
			}
			seen[*value.Number] = true
			if value.Result == nil {
				if !*value.Building {
					return invalid
				}
				continue
			}
			switch *value.Result {
			case "SUCCESS", "FAILURE", "UNSTABLE", "ABORTED", "NOT_BUILT":
			default:
				return invalid
			}
		}
	}
	return nil
}
