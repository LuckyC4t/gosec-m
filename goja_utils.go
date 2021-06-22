package gosec

import (
	"github.com/dop251/goja"
	"gosec-m/conf"
	"log"
	"reflect"
)

type utilstModule struct {
	DynamicRuleRunner
}

func (runner DynamicRuleRunner) createUtils() *goja.Object {
	vm := runner.GetRuntime()
	utilsObj := vm.NewObject()

	u := utilstModule{runner}
	for name, val := range u.Export() {
		utilsObj.Set(name, val)
	}

	return utilsObj
}

func (u utilstModule) Export() map[string]interface{} {
	return map[string]interface{}{
		"getGoType":   u.getGoType,
		"isType":      u.isType,
		"transformTo": u.transformTo,
	}
}

func (u utilstModule) getGoType(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	res := call.Argument(0).ExportType().String()

	return rt.ToValue(res)
}

func (u utilstModule) isType(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	from := call.Argument(0)
	check := call.Argument(1).String()

	return rt.ToValue(from.ExportType().String() == check)
}

func (u utilstModule) transformTo(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	from := call.Argument(0)
	realType := from.ExportType()
	toType := call.Argument(1).String()

	if realType.String() != toType {
		if debug := conf.Get("debug"); debug != nil && debug.(bool) {
			log.Printf("value of type %s cannot be converted to type %s",
				realType.String(), toType)
		}
		return goja.Null()
	}

	to := reflect.ValueOf(from.Export()).Convert(realType).Interface()

	return rt.ToValue(to)
}
