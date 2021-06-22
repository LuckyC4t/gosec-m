let metaData = gosec.NewMetaData()
metaData.ID = "G102"
metaData.Severity = gosec.MEDUIM
metaData.Confidence = gosec.High
metaData.What = "Binds to all network interfaces"

let calls = gosec.NewCallList()
calls.Add("net", "Listen")
calls.Add("crypto/tls", "Listen")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "pattern": new RegExp(/^(0.0.0.0|:).*$/),
    "for": ["*ast.CallExpr"],
}

function match(n, c) {
    let callExpr = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (callExpr === null) {
        return {"Issue": null, "Error": null}
    }

    if (callExpr.Args.length > 1) {
        let arg = callExpr.Args[1]
        if (utils.isType(arg, "*ast.BasicLit")) {
            let bl = utils.transformTo(arg, "*ast.BasicLit")
            try {
                let argStr = gosec.GetString(bl)

                if (rule.pattern.test(argStr)) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            } catch (e) {
                // pass
            }
        } else if (utils.isType(arg, "*ast.Ident")) {
            let ident = utils.transformTo(arg, "*ast.Ident")
            let values = gosec.GetIdentStringValues(ident)
            for (let value of values) {
                if (rule.pattern.test(value)) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            }
        } else if (callExpr.Args.length > 0) {
            let values = gosec.GetCallStringArgsValues(callExpr.Args[0], c)
            for (let value of values) {
                if (rule.pattern.test(value)) {
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