package xfmr

import (
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/runner"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/xfmr/gosec"
	"github.com/dop251/goja"
	"log"
)

func CreateGosec(ruleRunner *runner.DynamicRuleRunner) *goja.Object {
	vm := ruleRunner.GetRuntime()
	gosecObj := vm.NewObject()

	g := gosec.GosecModule{ruleRunner}

	for name, val := range g.Export() {
		if err := gosecObj.Set(name, val); err != nil {
			log.Fatal(err)
		}
	}

	return gosecObj
}
