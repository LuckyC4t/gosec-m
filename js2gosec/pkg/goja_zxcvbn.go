package pkg

import (
	"github.com/LuckyC4t/gosec-m/js2gosec/pkg/zxcvbn"
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
	"github.com/dop251/goja"
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
