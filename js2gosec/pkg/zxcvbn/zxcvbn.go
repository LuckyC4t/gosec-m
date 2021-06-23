package zxcvbn

import (
	"github.com/dop251/goja"
	"github.com/nbutton23/zxcvbn-go"
	"gosec-m/js2gosec/runner"
)

func (z ZxcvbnModule) PasswordStrength(call goja.FunctionCall) goja.Value {
	runtime := z.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(runtime.ToValue(runner.ErrWrongArgsNumber))
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
