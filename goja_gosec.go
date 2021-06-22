package gosec

import "github.com/dop251/goja"

type gosecModule struct {
	DynamicRuleRunner
}

func (runner DynamicRuleRunner) createGosec() *goja.Object {
	vm := runner.GetRuntime()
	gosecObj := vm.NewObject()

	g := gosecModule{runner}

	for name, val := range g.Export() {
		gosecObj.Set(name, val)
	}

	return gosecObj
}

func (g gosecModule) Export() map[string]interface{} {
	return map[string]interface{}{
		// call_list
		"NewCallList": g.NewCallList,

		// config
		"Nosec":            Nosec,
		"Audit":            Audit,
		"NoSecAlternative": NoSecAlternative,

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
		"High":        High,
		"Medium":      Medium,
		"Low":         Low,
		"NewMetaData": g.NewMetaData,
		"NewIssue":    g.NewIssue,

		// resolve
		"TryResolve": g.TryResolve,
	}
}
