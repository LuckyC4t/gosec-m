let metaData = gosec.NewMetaData()
metaData.ID = "G601"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.Medium
metaData.What = "Implicit memory aliasing in for loop."

let rule = {
    "metaData": metaData,
    "aliases": {},
    "rightBrace": 0,
    "acceptableAlias": [],
    "for": ["*ast.RangeStmt", "*ast.UnaryExpr", "*ast.ReturnStmt"],
    "cwe": {
        "id": "118",
        "desc": "The software does not restrict or incorrectly restricts operations within the boundaries of a" +
            " resource that is accessed using an index or pointer, such as memory or files.",
        "name": "Incorrect Access of Indexable Resource ('Range Error')"
    }
}

function containsUnary(exprs, expr) {
    for (let e of exprs) {
        if (e === expr) {
            return true
        }
    }
    return false
}

function match(n, c) {
    let typ = utils.getGoType(n)
    let node = undefined
    switch (typ) {
        case "*ast.RangeStmt":
            node = utils.transformTo(n, "*ast.RangeStmt")
            let key = utils.transformTo(node.Value, "*ast.Ident")
            if (key !== null && key.Obj !== null) {
                let assignment = utils.transformTo(key.Obj.Decl, "*ast.AssignStmt")
                if (assignment !== null) {
                    if (assignment.Lhs.length < 2) {
                        return {"Issue": null, "Error": null}
                    }

                    let object = utils.transformTo(assignment.Lhs[1], "*ast.Ident")
                    if (object !== null) {
                        rule.aliases[object.Obj] = undefined

                        if (rule.rightBrace < node.Body.Rbrace) {
                            rule.rightBrace = node.Body.Rbrace
                        }
                    }
                }
            }
            break
        case "*ast.UnaryExpr":
            node = utils.transformTo(n, "*ast.UnaryExpr")
            if (node.Pos() > rule.rightBrace) {
                rule.aliases = {}
                rule.acceptableAlias = []
            }

            if (rule.aliases.size === 0) {
                return {"Issue": null, "Error": null}
            }

            if (containsUnary(rule.acceptableAlias, node)) {
                return {"Issue": null, "Error": null}
            }

            let ident = utils.transformTo(node.X, "*ast.Ident")
            if (ident !== null && node.Op.String() === "&") {
                if (rule.aliases.hasOwnProperty(ident.Obj)) {
                    return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData
                            .Confidence), "Error": null}
                }
            }
            break
        case "*ast.ReturnStmt":
            node = utils.transformTo(n, "*ast.ReturnStmt")
            for (let item of node.Results) {
                let unary = utils.transformTo(item, "*ast.UnaryExpr")
                if (unary !== null && unary.Op.String() === "&") {
                    rule.acceptableAlias.push(unary)
                }
            }
            break
    }
    return {"Issue": null, "Error": null}
}