package pkg

import (
	"github.com/dop251/goja"
	"gosec-m/js2gosec/pkg/zxcvbn"
	"gosec-m/js2gosec/runner"
)

func CreatZXCVBN(ruleRunner *runner.DynamicRuleRunner) *goja.Object {
	vm := ruleRunner.GetRuntime()
	zxcObj := vm.NewObject()

	z := zxcvbn.ZxcvbnModule{ruleRunner}

	for name, val := range z.Export() {
		zxcObj.Set(name, val)
	}

	return zxcObj
}
