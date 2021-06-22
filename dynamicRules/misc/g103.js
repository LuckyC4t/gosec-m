let metaData = gosec.NewMetaData()
metaData.ID = "G103"
metaData.Severity = gosec.Low
metaData.Confidence = gosec.High
metaData.What = "Use of unsafe calls should be audited"

let rule = {
    "metaData": metaData,
    "pkg": "unsafe",
    "calls": ["Alignof", "Offsetof", "Sizeof", "Pointer"],
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    let res = gosec.MatchCallByPackage(n, c, rule.pkg, rule.calls)
    if (res[1]) {
        return {
            "Issue": gosec.NewIssue(c, n,
                rule.metaData.ID, rule.metaData.What,
                rule.metaData.Severity, rule.metaData.Confidence),
            "Error": null
        }
    }

    return {"Issue": null, "Error": null}
}