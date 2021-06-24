package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/runner"
)

type GosecModule struct {
	*runner.DynamicRuleRunner
}

func (g GosecModule) Export() map[string]interface{} {
	return map[string]interface{}{
		// call_list
		"NewCallList": g.newCallList,

		// config
		"Nosec":            gosec.Nosec,
		"Audit":            gosec.Audit,
		"NoSecAlternative": gosec.NoSecAlternative,

		// helpers
		"ConcatString":            g.concatString,
		"FindVarIdentities":       g.findVarIdentities,
		"GetBinaryExprOperands":   g.getBinaryExprOperands,
		"GetCallInfo":             g.getCallInfo,
		"GetCallStringArgsValues": g.getCallStringArgsValues,
		"GetInt":                  g.getInt,
		"GetIdentStringValues":    g.getIdentStringValues,
		"GetString":               g.getString,
		"MatchCallByPackage":      g.matchCallByPackage,

		// issue
		"High":        gosec.High,
		"Medium":      gosec.Medium,
		"Low":         gosec.Low,
		"NewMetaData": g.newMetaData,
		"NewIssue":    g.newIssue,

		// resolve
		"TryResolve": g.tryResolve,
	}
}
