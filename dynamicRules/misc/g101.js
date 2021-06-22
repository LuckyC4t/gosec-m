let metaData = gosec.NewMetaData()
metaData.ID = "G101"
metaData.Severity = gosec.High
metaData.Confidence = gosec.Low
metaData.What = "Potential hardcoded credentials"

let rule = {
    "metaData": metaData,
    "pattern": new RegExp(/passwd|pass|password|pwd|secret|token/i),
    "entropyThreshold": 80.0,
    "perCharThreshold": 3.0,
    "ignoreEntropy": false,
    "truncate": 16,
    "for": ["*ast.AssignStmt", "*ast.ValueSpec", "*ast.BinaryExpr"]
}


function truncate(s, n) {
    if (n > s.length) {
        return s
    }
    return s.substr(0, n)
}

function isHighEntropyString(str) {
    let s = truncate(str, rule.truncate)
    let info = zxcvbn.passwordStrength(s, [])
    let entropyPerChar = info.Entropy / s.length
    return (info.Entropy >= rule.entropyThreshold ||
        (info.Entropy >= (rule.entropyThreshold/2) &&
            entropyPerChar >= rule.perCharThreshold))
}

function matchAssign(assign, ctx) {
    for (let i of assign.Lhs) {
        let ident = utils.transformTo(i, "*ast.Ident")
        if (ident !== null) {
            if (rule.pattern.test(ident.Name)) {
                for (let e of assign.Rhs) {
                    try {
                        let val = gosec.GetString(e)
                        if (rule.ignoreEntropy || (!rule.ignoreEntropy && isHighEntropyString(val))) {
                            return {
                                "Issue": gosec.NewIssue(ctx, assign, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData.Confidence),
                                "Error": null
                            }
                        }
                    } catch (except) {
                        // if err != nil { // pass }
                    }
                }
            }
        }
    }
    return {"Issue": null, "Error": null}
}

function matchValueSpec(valueSpec, ctx) {
    for (let index in valueSpec.Names) {
        let ident = valueSpec.Names[index]
        if (rule.pattern.test(ident.Name) && valueSpec.Values != null) {
            if (valueSpec.Values.length <= index) {
                index = valueSpec.Values.length -1
            }
            try {
                let val = gosec.GetString(valueSpec.Values[index])
                if (rule.ignoreEntropy || (!rule.ignoreEntropy && isHighEntropyString(val))) {
                    return {
                        "Issue": gosec.NewIssue(ctx, valueSpec, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData.Confidence),
                        "Error": null
                    }
                }
            } catch (e) {
                // pass
            }
        }
    }
    return {"Issue": null, "Error": null}
}

function matchEqualityCheck(binaryExpr, ctx) {
    if (binaryExpr.Op.String() ===  "==" || binaryExpr.Op.String() === "!=") {
        if (utils.isType(binaryExpr.X, "*ast.Ident")) {
            let ident = utils.transformTo(binaryExpr.X, "*ast.Ident")
            if (rule.pattern.test(ident.Name)) {
                try {
                    let val = gosec.GetString(binaryExpr.Y)
                    if (rule.ignoreEntropy || (!rule.ignoreEntropy && isHighEntropyString(val))) {
                        return {
                            "Issue": gosec.NewIssue(ctx, binaryExpr, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData.Confidence),
                            "Error": null
                        }
                    }
                } catch (e) {
                    // pass
                }
            }
        }
    }
    return {"Issue": null, "Error": null}
}

function match(n, ctx) {
    let typ = utils.getGoType(n)
    let node = undefined

    switch (typ) {
        case "*ast.AssignStmt":
            node = utils.transformTo(n, "*ast.AssignStmt")
            return matchAssign(node, ctx)
        case "*ast.ValueSpec":
            node = utils.transformTo(n, "*ast.ValueSpec")
            return matchValueSpec(node, ctx)
        case "*ast.BinaryExpr":
            node = utils.transformTo(n, "*ast.BinaryExpr")
            return matchEqualityCheck(node, ctx)
    }

    return {"Issue": null, "Error": null}
}