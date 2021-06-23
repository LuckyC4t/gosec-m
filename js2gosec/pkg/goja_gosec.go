package pkg

import (
	"github.com/LuckyC4t/gosec-m/js2gosec/pkg/gosec"
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
	"github.com/dop251/goja"
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
