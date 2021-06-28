let metaData = gosec.NewMetaData()
metaData.ID = "G104"
metaData.Severity = gosec.Low
metaData.Confidence = gosec.High
metaData.What = "Errors unhandled."

// 白名单可以直接修改规则，不需要从配置文件加载
let whitelist = gosec.NewCallList()
whitelist.AddAll("bytes.Buffer", "Write", "WriteByte", "WriteRune", "WriteString")
whitelist.AddAll("fmt", "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln")
whitelist.AddAll("strings.Builder", "Write", "WriteByte", "WriteRune", "WriteString")
whitelist.Add("io.PipeWriter", "CloseWithError")
whitelist.Add("hash.Hash", "Write")

let rule = {
    "metaData": metaData,
    "whitelist": whitelist,
    "for": ["*ast.AssignStmt", "*ast.ExprStmt"]
}

function returnsError(callExpr, ctx) {
    let tv = ctx.Info.TypeOf(callExpr)
    if (tv !== null) {
        let typ = utils.getGoType(tv)
        switch (typ) {
            case "*types.Tuple":
            {
                let t = utils.transformTo(tv, "*types.Tuple")
                for (var pos = 0; pos < t.Len(); pos++) {
                    let variable = t.At(pos)
                    if (variable != null && variable.Type().String() === "error") {
                        return pos
                    }
                }
                break
            }
            case "*types.Named":
            {
                let t = utils.transformTo(tv, "*types.Named")
                if (t.String() === "error") {
                    return 0
                }
                break
            }
        }
    }
    return -1
}

function toStringSlice(values) {
    let res = []
    for (let value of values) {
        try {
            res.push(String(value))
        } catch (e) {
            console.log(e)
            //pass
        }
    }
    return res
}

function match(n, ctx) {
    let typ = utils.getGoType(n)
    switch (typ) {
        case "*ast.AssignStmt":
            var stmt = utils.transformTo(n, "*ast.AssignStmt")
            let cfg = ctx.Config
            try {
                if (cfg.IsGlobalEnabled(gosec.Audit) === true) {
                    for (let expr of stmt.Rhs) {
                        if (utils.isType(expr, "*ast.CallExpr") && rule.whitelist.ContainsCallExpr(expr, ctx) === null) {
                            let callExpr = utils.transformTo(expr, "*ast.CallExpr")
                            let pos = returnsError(callExpr, ctx)
                            if (pos < 0 || pos > stmt.Lhs.length) {
                                return {"Issue": null, "Error": null}
                            }
                            if (utils.isType(stmt.Lhs[pos], "*ast.Ident")) {
                                let id = utils.transformTo(stmt.Lhs[pos], "*ast.Ident")
                                if (id.Name === "_") {
                                    return {
                                        "Issue": gosec.NewIssue(ctx, n,
                                            rule.metaData.ID, rule.metaData.What,
                                            rule.metaData.Severity, rule.metaData.Confidence),
                                        "Error": null
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (e) {
                // pass
            }
            break
        case "*ast.ExprStmt":
            var stmt = utils.transformTo(n, "*ast.ExprStmt")
            let callExpr = utils.transformTo(stmt.X, "*ast.CallExpr")
            if (callExpr !== null && rule.whitelist.ContainsCallExpr(stmt.X, ctx) === null) {
                let pos = returnsError(callExpr, ctx)
                if (pos >= 0) {
                    return {
                        "Issue": gosec.NewIssue(ctx, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }

    }
    return {"Issue": null, "Error": null}
}