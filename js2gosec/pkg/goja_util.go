package pkg

import (
	"github.com/LuckyC4t/gosec-m/js2gosec/pkg/util"
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
	"github.com/dop251/goja"
)

func CreateUtils(ruleRunner *runner.DynamicRuleRunner) *goja.Object {
	vm := ruleRunner.GetRuntime()
	utilsObj := vm.NewObject()

	u := util.UtilstModule{ruleRunner}
	for name, val := range u.Export() {
		utilsObj.Set(name, val)
	}

	return utilsObj
}
