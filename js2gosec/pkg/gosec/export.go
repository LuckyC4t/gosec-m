package gosec

import (
	"gosec-m"
	"gosec-m/js2gosec/runner"
)

type GosecModule struct {
	*runner.DynamicRuleRunner
}

func (g GosecModule) Export() map[string]interface{} {
	return map[string]interface{}{
		// call_list
		"NewCallList": g.NewCallList,

		// config
		"Nosec":            gosec.Nosec,
		"Audit":            gosec.Audit,
		"NoSecAlternative": gosec.NoSecAlternative,

		// helpers
		"ConcatString":            g.ConcatString,
		"FindVarIdentities":       g.FindVarIdentities,
		"GetBinaryExprOperands":   g.GetBinaryExprOperands,
		"GetCallInfo":             g.GetCallInfo,
		"GetCallStringArgsValues": g.GetCallStringArgsValues,
		"GetInt":                  g.GetInt,
		"GetIdentStringValues":    g.GetIdentStringValues,
		"GetString":               g.GetString,
		"MatchCallByPackage":      g.MatchCallByPackage,

		// issue
		"High":        gosec.High,
		"Medium":      gosec.Medium,
		"Low":         gosec.Low,
		"NewMetaData": g.NewMetaData,
		"NewIssue":    g.NewIssue,

		// resolve
		"TryResolve": g.TryResolve,
	}
}
