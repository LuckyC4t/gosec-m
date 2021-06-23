package gosec

import "github.com/LuckyC4t/gosec-m/cwe"

func GetCweByRule(id string) *cwe.Weakness {
	cweID, ok := ruleToCWE[id]
	if ok && cweID != "" {
		return cwe.Get(cweID)
	}

	return cwe.GetOrEmpty(id)
}

func IsGosecID(id string) bool {
	_, has := ruleToCWE[id]
	return has
}
