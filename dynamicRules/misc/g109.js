let metaData = gosec.NewMetaData()
metaData.ID = "G109"
metaData.Severity = gosec.High
metaData.Confidence = gosec.Medium
metaData.What = "Potential Integer overflow made by strconv.Atoi result conversion to int16/32"

let calls = gosec.NewCallList()
calls.Add("strconv", "Atoi")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "for": ["*ast.FuncDecl", "*ast.AssignStmt", "*ast.CallExpr"]
}

function match(node, ctx) {
    let atoiVarObj = {}
    if (!ctx.PassedValues.hasOwnProperty(rule.metaData.ID)) {
        ctx.PassedValues[rule.metaData.ID] = atoiVarObj
    } else {
        atoiVarObj = ctx.PassedValues[rule.metaData.ID]
    }

    let typ = utils.getGoType(node)
    let n = undefined
    switch (typ) {
        case "*ast.AssignStmt":
            n = utils.transformTo(node, "*ast.AssignStmt")
            for (let expr of n.Rhs) {
                let callExpr = utils.transformTo(expr, "*ast.CallExpr")
                if (callExpr !== null && rule.calls.ContainsPkgCallExpr(callExpr, ctx, false) !== null) {
                    let idt = utils.transformTo(n.Lhs[0], "*ast.Ident")
                    if (idt !== null && idt.Name !== "_") {
                        atoiVarObj[idt.Obj] = n
                    }
                }
            }
            break
        case "*ast.CallExpr":
            n = utils.transformTo(node, "*ast.CallExpr")
            let fun = utils.transformTo(n.Fun, "*ast.Ident")
            if (fun !== null) {
                if (fun.Name === "int32" || fun.Name === "int16") {
                    let idt = utils.transformTo(n.Args[0], "*ast.Ident")
                    if (idt !== null) {
                        let nn = atoiVarObj[idt.Obj]
                        if (nn !== undefined) {
                            return {
                                "Issue": gosec.NewIssue(ctx, nn,
                                    rule.metaData.ID, rule.metaData.What,
                                    rule.metaData.Severity, rule.metaData.Confidence),
                                "Error": null
                            }
                        }
                    }
                }
            }
    }
    return {"Issue": null, "Error": null}
}