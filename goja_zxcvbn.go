package gosec

import (
	"github.com/dop251/goja"
	"github.com/nbutton23/zxcvbn-go"
)

type zxcvbnModule struct {
	DynamicRuleRunner
}

func (runner DynamicRuleRunner) creatZXCVBN() *goja.Object {
	vm := runner.GetRuntime()
	zxcObj := vm.NewObject()

	z := zxcvbnModule{runner}

	for name, val := range z.Export() {
		zxcObj.Set(name, val)
	}

	return zxcObj
}

func (z zxcvbnModule) Export() map[string]interface{} {
	return map[string]interface{}{
		"passwordStrength": z.PasswordStrength,
	}
}

func (z zxcvbnModule) PasswordStrength(call goja.FunctionCall) goja.Value {
	runtime := z.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(runtime.ToValue(ErrWrongArgsNumber))
	}

	password := call.Argument(0).String()
	userInputInterface := call.Argument(1).Export().([]interface{})

	userInputStr := make([]string, len(userInputInterface))
	for i, v := range userInputInterface {
		userInputStr[i] = v.(string)
	}

	info := zxcvbn.PasswordStrength(password, userInputStr)
	return runtime.ToValue(info)
}
