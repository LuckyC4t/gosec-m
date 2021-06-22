
# gosec-m - gosec规则动态化

## 初衷
在将gosec集成到流程中时，当添加新规则时，往往要重新编译gosec。对于我来说，觉得比较繁琐，于是想要将gosec的规则动态加载，这样添加或修改规则后就不用重新编译了。

## 使用
### 编译
```bash
cd cmd/gosec && go generate && go build .

./main -rule=dynamicRule /thescanpath
```
使用方法与gosec一致

### 规则
gosec.XXX基本与gosec原有用法一致
对于`if a, ok := b.(type); !ok {...}`语法，增加utils包用于兼容。
```js
let a = utils.transformTo(a, "type")
if (a !== null) {
    ...
}
```
utils包中方法有:
```js
utils.getGoType(v) string // 获取在go中类型的字符串
utils.isType(v, "type") bool // 是否可以类型转换
utils.transformTo(v, "type") variable or null // 强制类型转换，如果转换失败则返回null
```
#### 样例
```js
// 创建metadata
let metaData = gosec.NewMetaData()
metaData.ID = "string"
metaData.Severity = gosec.Medium // 漏洞等级
metaData.Confidence = gosec.High // 漏洞可信度
metaData.What = "string"

let rule = { // 一定得是rule变量
    "metaData": metaData,
    "for": ["*ast.CallExpr"], // 规则绑定于哪种ast节点上
    "cwe": { // cwe信息
        "id": "118",
        "desc": "The software does not restrict or incorrectly restricts operations within the boundaries of a" +
                " resource that is accessed using an index or pointer, such as memory or files.",
        "name": "Incorrect Access of Indexable Resource ('Range Error')"
    }
}

// 匹配函数，一定得是match，并有两个参数
function match(n, c) {
    if (true) {
        return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData
            .Confidence), "Error": null}
    }

    return {"Issue": null, "Error": null}
}
```