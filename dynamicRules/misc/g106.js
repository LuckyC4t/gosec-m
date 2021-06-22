let metaData = gosec.NewMetaData()
metaData.ID = "G106"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Use of ssh InsecureIgnoreHostKey should be audited"

let rule = {
    "metaData": metaData,
    "pkg": "golang.org/x/crypto/ssh",
    "calls": ["InsecureIgnoreHostKey"],
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