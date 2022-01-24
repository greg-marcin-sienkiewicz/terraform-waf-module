output "arn" {
  description = "The ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.waf.arn
}

output "capacity" {
  description = "The web ACL capacity units (WCUs) currently being used by this web ACL"
  value         = aws_wafv2_web_acl.waf.capacity
}
