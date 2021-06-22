let metaData = gosec.NewMetaData()
metaData.ID = "G304"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Potential file inclusion via variable"

let rule = {
    "metaData": metaData,
    "calls": gosec.NewCallList(),
    "pathJoin": gosec.NewCallList(),
    "clean": gosec.NewCallList(),
    "for": ["*ast.CallExpr"]
}

rule.pathJoin.Add("path/filepath", "Join")
rule.pathJoin.Add("path", "Join")
rule.clean.Add("path/filepath", "Clean")
rule.clean.Add("path/filepath", "Rel")
rule.calls.Add("io/ioutil", "ReadFile")
rule.calls.Add("os", "Open")
rule.calls.Add("os", "OpenFile")


function isJoinFunc(n, c) {
    let call = rule.pathJoin.ContainsPkgCallExpr(n, c, false)
    if (call !== null) {
        for (let arg of call.Args) {
            let binExp = utils.transformTo(arg, "*ast.BinaryExpr")
            if (binExp !== null) {
                let ret = gosec.FindVarIdentities(binExp, c)
                if (ret[1]) {
                    return true
                }
            }

            let ident = utils.transformTo(arg, "*ast.Ident")
            if (ident !== null) {
                let obj = c.Info.ObjectOf(ident)
                if (utils.isType(obj, "*types.Var") && !gosec.TryResolve(ident, c)) {
                    return true
                }
            }
        }
    }

    return false
}

function isFilepathClean(n, c) {
    if (n.Obj.Kind.String() !== "var") {
        return false
    }
    let node = utils.transformTo(n.Obj.Decl, "*ast.AssignStmt")
    if (node !== null) {
        let call = utils.transformTo(node.Rhs[0], "*ast.CallExpr")
        if (call !== null) {
            let clean = rule.clean.ContainsPkgCallExpr(call, c, false)
            if (clean !== null) {
                return true
            }
        }
    }
}


function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) {
        for (let arg of node.Args) {
            let callExpr = utils.transformTo(arg, "*ast.CallExpr")
            if (callExpr !== null) {
                if (isJoinFunc(callExpr, c)) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }

            let binExp = utils.transformTo(arg, "*ast.BinaryExpr")
            if (binExp !== null) {
                let ret = gosec.FindVarIdentities(binExp, c)
                if (ret[1]) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }

            let ident = utils.transformTo(arg, "*ast.Ident")
            if (ident !== null) {
                let obj = c.Info.ObjectOf(ident)
                if (utils.isType(obj, "*types.Var") && !gosec.TryResolve(ident, c) && !isFilepathClean(ident, c)) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }
        }
    }
    return {"Issue": null, "Error": null}
}