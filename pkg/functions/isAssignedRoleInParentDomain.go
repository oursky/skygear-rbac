package functions

import (
	"github.com/casbin/casbin/v2"
	"github.com/oursky/skygear-rbac/pkg/constants"
)

// CreateIsAssignedRoleInParentDomain Generates function matcher to find if role is assigned to user in domain or parent domains
func CreateIsAssignedRoleInParentDomain(enforcer *casbin.Enforcer) func(args ...interface{}) (interface{}, error) {
	return func(args ...interface{}) (interface{}, error) {
		subject := args[0].(string)
		role := args[1].(string)
		domain := args[2].(string)

		// Find in what domains is subject assigned the role
		raw := enforcer.GetFilteredNamedGroupingPolicy("g", 0, subject)

		domains := []string{}
		for _, policy := range raw {
			if policy[1] == role {
				domains = append(domains, policy[2])
			}

		}

		raw = enforcer.GetNamedGroupingPolicy("g")

		// Find if a domain is parent of policy domain
		for _, parent := range domains {
			hasLink, err := enforcer.GetRoleManager().HasLink(parent, domain, constants.IsDomain)

			if err != nil {
				return nil, err
			}

			if hasLink {
				return true, err
			}
		}

		return false, nil
	}
}
