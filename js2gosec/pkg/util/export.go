package util

import (
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
)

type UtilstModule struct {
	*runner.DynamicRuleRunner
}

func (u UtilstModule) Export() map[string]interface{} {
	return map[string]interface{}{
		"getGoType":   u.getGoType,
		"isType":      u.isType,
		"transformTo": u.transformTo,
	}
}
