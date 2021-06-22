let metaData = gosec.NewMetaData()
metaData.ID = "G204"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High

let calls = gosec.NewCallList()
calls.Add("os/exec", "Command")
calls.Add("os/exec", "CommandContext")
calls.Add("syscall", "Exec")
calls.Add("syscall", "ForkExec")
calls.Add("syscall", "StartProcess")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "for": ["*ast.CallExpr"]
}

function isContext(n, ctx) {
    try {
        let ret = gosec.GetCallInfo(n, ctx)
        if (ret[0] === "exec" && ret[1] === "CommandContext") {
            return true
        }
    } catch (e) {
        return false
    }

    return false
}

function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) {
        let args = node.Args
        if (isContext(n, c)) {
            args = args.slice(1)
        }

        for (let arg of args) {
            let ident = utils.transformTo(arg, "*ast.Ident")
            if (ident !== null) {
                let obj = c.Info.ObjectOf(ident)
                if (utils.isType(obj, "*types.Var") && !gosec.TryResolve(ident, c)) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, "Subprocess launched with variable",
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            } else if(!gosec.TryResolve(arg, c)) {
                return {
                    "Issue": gosec.NewIssue(c, n,
                        rule.metaData.ID, "Subprocess launched with function call as argument or cmd arguments",
                        rule.metaData.Severity, rule.metaData.Confidence),
                    "Error": null
                }
            }
        }
    }
    return {"Issue": null, "Error": null}
}