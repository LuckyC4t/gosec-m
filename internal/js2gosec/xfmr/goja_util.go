package xfmr

import (
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/runner"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/xfmr/util"
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
