let metaData = gosec.NewMetaData()
metaData.ID = "G201"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "SQL string formatting"

let callList = gosec.NewCallList()
callList.AddAll("*database/sql.DB", "Query", "QueryContext", "QueryRow", "QueryRowContext")
callList.AddAll("*database/sql.Tx", "Query", "QueryContext", "QueryRow", "QueryRowContext")

let fmtCalls = gosec.NewCallList()
fmtCalls.AddAll("fmt", "Sprint", "Sprintf", "Sprintln", "Fprintf")

let noIssue = gosec.NewCallList()
noIssue.AddAll("os", "Stdout", "Stderr")

let noIssueQuoted = gosec.NewCallList()
noIssueQuoted.Add("github.com/lib/pq", "QuoteIdentifier")

let rule = {
    "callList": callList,
    "fmtCalls": fmtCalls,
    "noIssue": noIssue,
    "noIssueQuoted": noIssueQuoted,
    "metaData": metaData,
    "patterns": [new RegExp(/(SELECT|DELETE|INSERT|UPDATE|INTO|FROM|WHERE) /i),
                new RegExp(/%[^bdoxXfFp]/)],
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

function constObject(e, c) {
    let n = utils.transformTo(e, "*ast.Ident")
    if (n === null) {
        return false
    }

    if (n.Obj !== null) {
        return n.Obj.Kind.String() === "const"
    }

    for (let file of c.PkgFiles) {
        let node = file.Scope.Objects[n.String()]
        if (node !== undefined) {
            return node.Kind.String() === "const"
        }
    }

    return false
}

function checkFormatting(n, ctx) {
    let argIndex = 0
    let node = rule.fmtCalls.ContainsPkgCallExpr(n, ctx, false)
    if (node !== null) {
        let sel = utils.transformTo(node.Fun, "*ast.SelectorExpr")
        if (sel !== null && sel.Sel.Name === "Fprintf") {
            let arg = utils.transformTo(node.Args[0], "*ast.SelectorExpr")
            if (arg !== null) {
                let ident = utils.transformTo(arg.X, "*ast.Ident")
                if (ident !== null && rule.noIssue.Contains(ident.Name, arg.Sel.Name)) {
                    return null
                }
            }

            argIndex = 1
        }

        if (node.Args.length === 0) {
            return null
        }

        let formatter = ""

        let argExpr = utils.transformTo(node.Args[argIndex], "*ast.BinaryExpr")
        if (argExpr !== null) {
            let ret = gosec.ConcatString(argExpr)
            if (ret[1]) {
                formatter = ret[0]
            }
        } else {
            try {
                let arg = gosec.GetString(node.Args[argIndex])
                formatter = arg
            } catch (e) {}
        }

        if (formatter.length <= 0) {
            return null
        }

        if (argIndex+1 < node.Args.length) {
            let allSafe = true
            for (let arg of node.Args.slice(argIndex+1)) {
                let n = rule.noIssueQuoted.ContainsPkgCallExpr(arg, ctx, true)
                if (n === null && !constObject(arg, ctx)) {
                    allSafe = false
                    break
                }
            }
            if (allSafe) {
                return null
            }
        }

        if (MatchPatterns(formatter)) {
            return gosec.NewIssue(ctx, n,
                rule.metaData.ID, rule.metaData.What,
                rule.metaData.Severity, rule.metaData.Confidence)
        }
    }
    return null
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


        let ident = utils.transformTo(query, "*ast.Ident")
        if (ident !== null && ident.Obj !== null) {
            let decl = ident.Obj.Decl
            let assign = utils.transformTo(decl, "*ast.AssignStmt")
            if (assign !== null) {
                for (let expr of assign.Rhs) {
                    let issue = checkFormatting(expr, ctx)
                    if (issue !== null) {
                        return {"Issue": issue, "Error": null}
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