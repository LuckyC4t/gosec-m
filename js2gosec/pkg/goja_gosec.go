package pkg

import (
	"github.com/dop251/goja"
	"gosec-m/js2gosec/pkg/gosec"
	"gosec-m/js2gosec/runner"
)

func CreateGosec(ruleRunner *runner.DynamicRuleRunner) *goja.Object {
	vm := ruleRunner.GetRuntime()
	gosecObj := vm.NewObject()

	g := gosec.GosecModule{ruleRunner}

	for name, val := range g.Export() {
		gosecObj.Set(name, val)
	}

	return gosecObj
}
