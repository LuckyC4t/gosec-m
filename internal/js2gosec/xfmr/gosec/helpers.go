package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
	"go/ast"
)

func (g GosecModule) getCallInfo(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	ctx := call.Argument(1).Export().(*gosec.Context)

	typ, method, err := gosec.GetCallInfo(n, ctx)
	if err != nil {
		panic(rt.NewGoError(err))
	}

	return rt.ToValue([]string{typ, method})
}

func (g GosecModule) getString(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	str, err := gosec.GetString(n)
	if err != nil {
		panic(rt.NewGoError(err))
	}
	return rt.ToValue(str)
}

func (g GosecModule) getIdentStringValues(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	id := call.Argument(0).Export().(*ast.Ident)

	res := gosec.GetIdentStringValues(id)

	return rt.ToValue(res)
}

func (g GosecModule) getCallStringArgsValues(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	ctx := call.Argument(1).Export().(*gosec.Context)

	res := gosec.GetCallStringArgsValues(n, ctx)

	return rt.ToValue(res)
}

func (g GosecModule) matchCallByPackage(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 4 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	c := call.Argument(1).Export().(*gosec.Context)
	pkg := call.Argument(2).String()
	restPara := call.Argument(3).Export().([]interface{})
	names := make([]string, len(restPara))
	for i := range restPara {
		names[i] = restPara[i].(string)
	}
	res := make([]interface{}, 2)
	res[0], res[1] = gosec.MatchCallByPackage(n, c, pkg, names...)

	return rt.ToValue(res)
}

func (g GosecModule) getBinaryExprOperands(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	be := call.Argument(0).Export().(*ast.BinaryExpr)
	res := gosec.GetBinaryExprOperands(be)
	return rt.ToValue(res)
}

func (g GosecModule) concatString(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(*ast.BinaryExpr)
	res := make([]interface{}, 2)
	res[0], res[1] = gosec.ConcatString(n)
	return rt.ToValue(res)
}

func (g GosecModule) findVarIdentities(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(*ast.BinaryExpr)
	c := call.Argument(1).Export().(*gosec.Context)

	res := make([]interface{}, 2)
	res[0], res[1] = gosec.FindVarIdentities(n, c)
	return rt.ToValue(res)
}

func (g GosecModule) getInt(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	res, err := gosec.GetInt(n)
	if err != nil {
		panic(rt.NewGoError(err))
	}

	return rt.ToValue(res)
}
