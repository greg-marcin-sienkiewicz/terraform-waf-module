resource "aws_wafv2_ip_set" "block_ip_set" {
  name               = "BlockIpSet"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = flatten(["1.1.1.1/32", "2.2.2.2/32", var.ip_set_addresses])
}

resource "aws_wafv2_rule_group" "custom_rule" {
  name        = "CustomRuleGroup"
  description = "A custom rule group to block by IP Set"
  scope       = "REGIONAL"
  capacity    = 10

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CustomRuleGroup"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "BlockByIpSet"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.block_ip_set.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockByIpSet"
      sampled_requests_enabled   = true
    }
  }
}
