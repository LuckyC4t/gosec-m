package zxcvbn

import (
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
)

type ZxcvbnModule struct {
	*runner.DynamicRuleRunner
}

func (z ZxcvbnModule) Export() map[string]interface{} {
	return map[string]interface{}{
		"passwordStrength": z.PasswordStrength,
	}
}
