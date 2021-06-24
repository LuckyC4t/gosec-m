
# gosec-m - gosec规则动态化

## 背景

在gosec与流水线继承的过程中，时常遇到因为解决漏报或者误报而去添加或修改gosec规则，又因为gosec规则以代码形式编译进二进制文件中，只要改动了规则，就要重新编译整个gosec并更新流水线中的二进制执行文件。

为了方便规则的改动，就产生了对gosec进行修改的想法，于是就有了这个项目——用js编写gosec规则并动态加载。
## 编译

本项目使用Go 1.16+ (with Go module) 
```bash
cd cmd/gosec && go generate && go build
```

## 使用说明

只对gosec加载规则做了修改，使用方法基本与gosec原版一致。

特别说明：因为是加载js，所以要明确js文件所在的文件夹。

例如:
```bash
gosec -rule=/tmp/dynamicRule/ {gosec参数} {需要扫描的路径}
```
如果需要输出js加载时后的输出，则需要添加`-debug`参数。
```bash
gosec -rule=/tmp/dynamicRule/ -debug {gosec参数} {需要扫描的路径}
```

### 规则

对于原有规则中用到的gosec包中的函数，基本都做了转换，例如原有规则调用了`gosec.NewCallList()`，js中沿用这种写法就行。

对于`if a, ok := b.(type); ok {...}`语法，增加utils包用于替代。
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

[template](dynamicRules/template)
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
    if (true) { // 如果存在漏洞
        return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData
            .Confidence), "Error": null}
    }
    
    // 不存在
    return {"Issue": null, "Error": null}
}
```

## 参考项目

- [gosec](https://github.com/securego/gosec) — Golang security checker

- [goja](https://github.com/dop251/goja) — ECMAScript/JavaScript engine in pure Go

## 维护者

[@LuckyC4t](https://github.com/LuckyC4t)

## 使用许可

Apache License Version 2.0.