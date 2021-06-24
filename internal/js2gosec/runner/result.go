package runner

import "github.com/LuckyC4t/gosec-m"

type GojaRuleResult struct {
	Issue *gosec.Issue
	Error string
}
