package util

import (
	"github.com/LuckyC4t/gosec-m/internal/conf"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
	"log"
	"reflect"
)

func (u UtilstModule) getGoType(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	res := call.Argument(0).ExportType().String()

	return rt.ToValue(res)
}

func (u UtilstModule) isType(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	from := call.Argument(0)
	if from.ExportType() == nil {
		return rt.ToValue(false)
	}

	check := call.Argument(1).String()

	return rt.ToValue(from.ExportType().String() == check)
}

func (u UtilstModule) transformTo(call goja.FunctionCall) goja.Value {
	rt := u.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	from := call.Argument(0)
	realType := from.ExportType()
	if realType == nil {
		return goja.Null()
	}

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
