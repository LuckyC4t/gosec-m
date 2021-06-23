package pkg

import (
	"github.com/dop251/goja"
	"gosec-m/js2gosec/pkg/util"
	"gosec-m/js2gosec/runner"
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
