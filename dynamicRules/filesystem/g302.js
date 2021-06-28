let metaData = gosec.NewMetaData()
metaData.ID = "G302"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Expect file permissions to be 0600 or less"

let rule = {
    "metaData": metaData,
    "mode": parseInt("0600", 8),
    "pkgs": ["os"],
    "calls": ["OpenFile", "Chmod"],
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    for (let pkg of rule.pkgs) {
        let ret = gosec.MatchCallByPackage(n, c, pkg, rule.calls)
        let callexpr = ret[0]
        let matched = ret[1]

        if (matched) {
            let modeArg = callexpr.Args[callexpr.Args.length-1]
            try {
                let mode = gosec.GetInt(modeArg)
                if (mode > rule.mode) {
                    return {
                        "Issue": gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What,
                            rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            } catch (e) {

            }
        }
    }

    return {"Issue": null, "Error": null}
}