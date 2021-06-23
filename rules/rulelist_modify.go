package rules

import (
	"errors"
	gosec "github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/conf"
	"github.com/LuckyC4t/gosec-m/cwe"
	"github.com/LuckyC4t/gosec-m/js2gosec"
	"go/ast"
	"log"
	"os"
	"path/filepath"
)

func Generate(filters ...RuleFilter) RuleList {
	rules := []RuleDefinition{}

	rulePath := ""
	if v := conf.Get("rulePath"); v != nil {
		rulePath = v.(string)
	}

	dynamicRules := loadDynamicRules(rulePath)
	rules = append(rules, dynamicRules...)

	ruleMap := make(map[string]RuleDefinition)

RULES:
	for _, rule := range rules {
		for _, filter := range filters {
			if filter(rule.ID) {
				continue RULES
			}
		}
		ruleMap[rule.ID] = rule
	}
	return ruleMap
}

// 动态规则加载
func loadDynamicRules(path string) []RuleDefinition {
	ruleFiles := []string{}
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			if filepath.Ext(info.Name()) == ".js" {
				ruleFiles = append(ruleFiles, p)
			}
		}
		return nil
	})

	if err != nil {
		log.Println(err)
		return []RuleDefinition{}
	}

	rules := []RuleDefinition{}
	// 加载规则
	for _, ruleFile := range ruleFiles {
		ruleContent, err := os.ReadFile(ruleFile)
		if err != nil {
			log.Printf("load rule %s error: %s", ruleFile, err.Error())
			break
		}

		rule := loadGojaFile(ruleFile, ruleContent)

		// 没加载成功的就忽略
		if rule.Create != nil {
			rules = append(rules, rule)
		}
	}
	return rules
}

func loadGojaFile(file string, context []byte) RuleDefinition {
	runner := js2gosec.NewRunner()
	js2gosec.InitRunner(runner)

	vm := runner.GetRuntime()
	output, err := vm.RunScript(file, string(context))
	if err != nil {
		log.Printf("runtime error: %s", err)
		return RuleDefinition{}
	}

	if debug := conf.Get("debug"); debug != nil && debug.(bool) {
		log.Println(output.String())
	}

	// 获取rule信息
	rule := vm.Get("rule")
	if rule == nil {
		return RuleDefinition{}
	}
	ruleInfo := rule.Export().(map[string]interface{})

	metaData := *(ruleInfo["metaData"].(*gosec.MetaData))

	// 获取cwe并注册
	if cweContent, has := ruleInfo["cwe"]; has {
		cweInfo := cweContent.(map[string]interface{})
		// 不覆盖原有cwe对应关系
		if !gosec.IsGosecID(cweInfo["id"].(string)) {
			weakness := cwe.Weakness{
				ID:          cweInfo["id"].(string),
				Name:        cweInfo["name"].(string),
				Description: cweInfo["desc"].(string),
			}

			cwe.Set(metaData.ID, &weakness)
		}
	}

	// 获取rule执行函数match，并用ruleTemplate来实现Rule接口
	var match func(node ast.Node, context *gosec.Context) js2gosec.GojaRuleResult
	gojaMatchFunc := vm.Get("match")
	if gojaMatchFunc == nil {
		return RuleDefinition{}
	}
	err = vm.ExportTo(gojaMatchFunc, &match)
	if err != nil {
		log.Printf("bind match func error: %s", err)
		return RuleDefinition{}
	}

	return RuleDefinition{
		ID:          metaData.ID,
		Description: metaData.What, // Description实际中没用到，用到是what
		// 自定义creat函数，转换动态规则结果
		Create: func(id string, c gosec.Config) (gosec.Rule, []ast.Node) {
			rule := DynamicRule{
				id: id,
				match: func(node ast.Node, context *gosec.Context) (*gosec.Issue, error) {
					res := match(node, context)
					if res.Error != "null" {
						return res.Issue, errors.New(res.Error)
					}
					return res.Issue, nil
				},
			}

			// 构造绑定规则的类型
			var nodes []ast.Node
			for _, typ := range ruleInfo["for"].([]interface{}) {
				nodes = append(nodes, js2gosec.GetNewAstNodeByType(typ.(string)))
			}

			return &rule, nodes
		},
	}
}
