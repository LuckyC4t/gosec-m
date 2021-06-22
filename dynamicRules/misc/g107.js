let metaData = gosec.NewMetaData()
metaData.ID = "G107"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.Medium
metaData.What = "Potential HTTP request made with variable url"

let calls = gosec.NewCallList()
calls.AddAll("net/http", "Do", "Get", "Head", "Post", "PostForm", "RoundTrip")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "for": ["*ast.CallExpr"]
}

function ResolveVar(n, c) {
    if (n.Args.length > 0) {
        let arg = n.Args[0]
        if (utils.isType(arg, "*ast.Ident")) {
            let ident = utils.transformTo(arg, "*ast.Ident")
            let obj = c.Info.ObjectOf(ident)
            if (utils.isType(obj, "*types.Var")) {
                let scope = c.Pkg.Scope()
                if (scope !== null && scope.Lookup(ident.Name) !== null) {
                    return true
                }
                if (!gosec.TryResolve(ident, c)) {
                    return true
                }
            }
        }
    }
    return false
}

function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) { // != undefined
        if (ResolveVar(node, c)) {
            return {
                "Issue": gosec.NewIssue(c, n,
                    rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData.Confidence),
                "Error": null
            }
        }

    }

    return {
        "Issue": null,
        "Error": null
    }
}