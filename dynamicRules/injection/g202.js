let metaData = gosec.NewMetaData()
metaData.ID = "G202"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "SQL string concatenation"

let callList = gosec.NewCallList()
callList.AddAll("*database/sql.DB", "Query", "QueryContext", "QueryRow", "QueryRowContext")
callList.AddAll("*database/sql.Tx", "Query", "QueryContext", "QueryRow", "QueryRowContext")

let rule = {
    "callList": callList,
    "metaData": metaData,
    "patterns": [new RegExp(/(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) /i)],
    "for": ["*ast.AssignStmt", "*ast.ExprStmt"]
}

function MatchPatterns(str) {
    for (let pattern of rule.patterns) {
        if (!pattern.test(str)) {
            return false
        }
    }
    return true
}

function checkObject(n, c) {
    if (n.Obj !== null) {
        return n.Obj.Kind.String() !== "var" && n.Obj.Kind.String() !== "func"
    }

    for (let file of c.PkgFiles) {
        let node = file.Scope.Objects[n.String()]
        if (node !== undefined) {
            return node.Kind.String() !== "var" && node.Kind.String() !== "func"
        }
    }
    return false
}

function checkQuery(call, ctx) {
    try {
        let res = gosec.GetCallInfo(call, ctx)
        let fnName = res[1]
        let query = undefined
        if (fnName.endsWith("Context")) {
            query = call.Args[1]
        } else {
            query = call.Args[0]
        }

        let be = utils.transformTo(query, "*ast.BinaryExpr")
        if (be !== null) {
            let operands = gosec.GetBinaryExprOperands(be)
            let start = utils.transformTo(operands[0], "*ast.BasicLit")
            if (start !== null) {
                try {
                    let str = gosec.GetString(start)
                    if (!MatchPatterns(str)) {
                        return {"Issue": null, "Error": null}
                    }
                } catch (e) {}
                for (let op of operands.slice(1)) {
                    if (utils.isType(op, "*ast.BasicLit")) {
                        continue
                    }

                    let nn = utils.transformTo(op, "*ast.Ident")
                    if (nn !== null) {
                        if (checkObject(nn, ctx)) {
                            continue
                        }
                    }

                    return {
                        "Issue": gosec.NewIssue(ctx, be,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }
        }
    } catch (e) {
        return {"Issue": null, "Error": e}
    }
    return {"Issue": null, "Error": null}
}

function match(n, ctx) {
    let typ = utils.getGoType(n)
    let stmt = undefined
    switch (typ) {
        case "*ast.AssignStmt":
            stmt = utils.transformTo(n, "*ast.AssignStmt")
            for (let expr of stmt.Rhs) {
                let sqlQueryCall = utils.transformTo(expr, "*ast.CallExpr")
                if (sqlQueryCall !== null && rule.callList.ContainsCallExpr(expr, ctx) != null) {
                    return checkQuery(sqlQueryCall, ctx)
                }
            }
            break
        case "*ast.ExprStmt":
            stmt = utils.transformTo(n, "*ast.ExprStmt")
            let sqlQueryCall = utils.transformTo(stmt.X, "*ast.CallExpr")
            if (sqlQueryCall !== null && rule.callList.ContainsCallExpr(stmt.X, ctx) != null) {
                return checkQuery(sqlQueryCall, ctx)
            }
            break
    }
    return {"Issue": null, "Error": null}
}