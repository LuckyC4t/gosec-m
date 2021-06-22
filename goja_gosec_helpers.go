package gosec

import (
	"github.com/dop251/goja"
	"go/ast"
)

func (g gosecModule) GetCallInfo(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	ctx := call.Argument(1).Export().(*Context)

	typ, method, err := GetCallInfo(n, ctx)
	if err != nil {
		panic(rt.NewGoError(err))
	}

	return rt.ToValue([]string{typ, method})
}

func (g gosecModule) GetString(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	str, err := GetString(n)
	if err != nil {
		panic(rt.NewGoError(err))
	}
	return rt.ToValue(str)
}

func (g gosecModule) GetIdentStringValues(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	id := call.Argument(0).Export().(*ast.Ident)

	res := GetIdentStringValues(id)

	return rt.ToValue(res)
}

func (g gosecModule) GetCallStringArgsValues(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	ctx := call.Argument(1).Export().(*Context)

	res := GetCallStringArgsValues(n, ctx)

	return rt.ToValue(res)
}

func (g gosecModule) MatchCallByPackage(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 4 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	c := call.Argument(1).Export().(*Context)
	pkg := call.Argument(2).String()
	restPara := call.Argument(3).Export().([]interface{})
	names := make([]string, len(restPara))
	for i := range restPara {
		names[i] = restPara[i].(string)
	}
	res := make([]interface{}, 2)
	res[0], res[1] = MatchCallByPackage(n, c, pkg, names...)

	return rt.ToValue(res)
}

func (g gosecModule) GetBinaryExprOperands(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	be := call.Argument(0).Export().(*ast.BinaryExpr)
	res := GetBinaryExprOperands(be)
	return rt.ToValue(res)
}

func (g gosecModule) ConcatString(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(*ast.BinaryExpr)
	res := make([]interface{}, 2)
	res[0], res[1] = ConcatString(n)
	return rt.ToValue(res)
}

func (g gosecModule) FindVarIdentities(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 2 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(*ast.BinaryExpr)
	c := call.Argument(1).Export().(*Context)

	res := make([]interface{}, 2)
	res[0], res[1] = FindVarIdentities(n, c)
	return rt.ToValue(res)
}

func (g gosecModule) GetInt(call goja.FunctionCall) goja.Value {
	rt := g.GetRuntime()

	if len(call.Arguments) != 1 {
		panic(rt.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	res, err := GetInt(n)
	if err != nil {
		panic(rt.NewGoError(err))
	}

	return rt.ToValue(res)
}
