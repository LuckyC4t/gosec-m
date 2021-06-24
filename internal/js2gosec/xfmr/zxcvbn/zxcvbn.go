package zxcvbn

import (
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
	"github.com/nbutton23/zxcvbn-go"
)

func (z ZxcvbnModule) passwordStrength(call goja.FunctionCall) goja.Value {
	runtime := z.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(runtime.ToValue(errors.ErrWrongArgsNumber))
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
