resource "aws_wafv2_web_acl" "waf" {
  name        = var.web_acl_name
  description = "AWS managed rule groups."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = var.managed_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"

          dynamic "excluded_rule" {
            for_each = rule.value.excluded_rule
            content {
              name = excluded_rule.value
            }
          }
        }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = var.web_acl_name
    sampled_requests_enabled   = false
  }

  tags = merge(var.tags)
}

resource "aws_wafv2_web_acl_logging_configuration" "waf" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.waf.arn
}

resource "aws_wafv2_web_acl_association" "waf" {
  for_each     = toset(var.alb_arn)
  resource_arn = each.key
  web_acl_arn  = aws_wafv2_web_acl.waf.arn
}
