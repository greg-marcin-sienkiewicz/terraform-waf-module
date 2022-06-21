variable "alb_arn" {
  description = "List of ARN(s) of the Application Load Balancers (ALB) to associate WAF rules"
  type        = list(string)
}

# AWS Managed Rules rule groups list
# https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html

variable "managed_rules" {
  description = "List of AWS Managed WAF rules to apply to Web ACLs."

  type = list(object({
    name            = string
    priority        = number
    override_action = string
    excluded_rule   = list(string)
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
  description = "Name for the Web ACL."
  type        = string
}

variable "tags" {
  description = "(Optional) An map of key:value pairs to associate with all resources in the module."
  type        = map(string)
  default     = {}
}

variable "ip_set_addresses" {
  description = "An array of strings that specify one or more IPv4 addresses or blocks of IPv4 addresses in CIDR notation."
  type        = list(string)
  default     = []
}
