package zxcvbn

import (
	"gosec-m/js2gosec/runner"
)

type ZxcvbnModule struct {
	*runner.DynamicRuleRunner
}

func (z ZxcvbnModule) Export() map[string]interface{} {
	return map[string]interface{}{
		"passwordStrength": z.PasswordStrength,
	}
}
