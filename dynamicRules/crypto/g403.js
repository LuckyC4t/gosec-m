let metaData = gosec.NewMetaData()
metaData.ID = "G403"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High

let calls = gosec.NewCallList()
calls.Add("crypto/rsa", "GenerateKey")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "bits": 2048,
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    let callExpr = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (callExpr !== null) {
        try {
            let bits = gosec.GetInt(callExpr.Args[1])
            if (bits < rule.bits) {
                return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, "RSA keys should be at least "+rule.bits+" bits", rule.metaData.Severity, rule.metaData
                        .Confidence), "Error": null}
            }
        } catch (e) { }
    }
    return {"Issue": null, "Error": null}
}