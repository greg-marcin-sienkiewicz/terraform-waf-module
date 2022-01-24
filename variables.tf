variable "alb_arn" {
  description = "ARN of the Application Load Balancer (ALB) to associate WAF rules"
  type        = string
}

# AWS Managed Rules rule groups list
# https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html

variable "managed_rules" {
  description = "List of AWS Managed WAF rules to apply to Web ACLs."

  type = list(object({
    name            = string
    priority        = number
    override_action = string
  }))

  validation {
    condition = alltrue([for rule in var.managed_rules : contains([
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesAdminProtectionRuleSet",
      "AWSManagedRulesKnownBadInputsRuleSet",
      "AWSManagedRulesSQLiRuleSet",
      "AWSManagedRulesLinuxRuleSet",
      "AWSManagedRulesUnixRuleSet",
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesAnonymousIpList",
      "AWSManagedRulesBotControlRuleSet",
    ], rule.name)])
    error_message = "Unsupported AWS Managed Rule provided."
  }

  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl#override-action
  validation {
    condition     = alltrue([for rule in var.managed_rules : contains(["none", "count"], rule.override_action)])
    error_message = "Unsupported override action, valid inputs are 'none' and 'count'."
  }

}

variable "waf_log_group_name" {
  description = "Name of Amazon CloudWatch Logs log group used by WAF."
  type        = string
}

variable "retention_in_days" {
  description = "Specifies the number of days you want to retain log events in the specified log group."
  type        = string
}

variable "web_acl_name" {
  description = "Name for the Web ACL"
  type        = string
}