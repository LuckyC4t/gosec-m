let metaData = gosec.NewMetaData()
metaData.ID = "G404"
metaData.Severity = gosec.High
metaData.Confidence = gosec.Medium
metaData.What = "Use of weak random number generator (math/rand instead of crypto/rand)"

let rule = {
    "metaData": metaData,
    "funcNames": ["New", "Read", "Float32", "Float64", "Int", "Int31",
        "Int31n", "Int63", "Int63n", "Intn", "NormalFloat64", "Uint32", "Uint64"],
    "packagePath": "math/rand",
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    for (let funcName of rule.funcNames) {
        let ret = gosec.MatchCallByPackage(n, c, rule.packagePath, [funcName])
        if (ret[1]) {
            return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData
                    .Confidence), "Error": null}
        }
    }

    return {"Issue": null, "Error": null}
}