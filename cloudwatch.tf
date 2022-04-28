data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "cloudwatch_waf_kms" {
  statement {
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
        data.aws_caller_identity.current.arn,
      ]
    }

    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    principals {
      type        = "Service"
      identifiers = ["logs.us-east-1.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"

      values = ["arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:aws-waf-logs-*"]
    }
  }
}

resource "aws_kms_key" "cloudwatch_waf" {
  description  = "aws-waf-logs-${var.waf_log_group_name}-key"
  key_usage    = "ENCRYPT_DECRYPT"
  multi_region = true

  policy = data.aws_iam_policy_document.cloudwatch_waf_kms.json

  tags = merge(var.tags)
}

resource "aws_kms_alias" "cloudwatch_waf" {
  name          = "alias/aws-waf-logs-${var.waf_log_group_name}-key"
  target_key_id = aws_kms_key.cloudwatch_waf.key_id
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.waf_log_group_name}"
  retention_in_days = var.retention_in_days
  kms_key_id        = aws_kms_key.cloudwatch_waf.arn

  tags = merge(var.tags)
}

###=============== CloudWatch Log Insights - Queries   =============== ###

resource "aws_cloudwatch_query_definition" "tail" {
  name = "WAF/Tail View (${var.waf_log_group_name})"

  log_group_names = [aws_cloudwatch_log_group.waf.name]

  query_string = <<EOF
fields @timestamp as Timestamp,
  action as Action,
  terminatingRuleId as Rule,
  httpRequest.clientIp as Request_IP,
  httpRequest.country as Request_Country,
  httpRequest.httpMethod as Request_Method,
  httpRequest.uri as URI
| sort @timestamp desc
| limit 100
EOF
}

resource "aws_cloudwatch_query_definition" "filter_by_clientip" {
  name = "WAF/Filter by Client IP (${var.web_acl_name})"

  log_group_names = [aws_cloudwatch_log_group.waf.name]

  query_string = <<EOF
fields @timestamp as Timestamp,
  action as Action,
  httpRequest.country as Request_Country,
  httpRequest.httpMethod as Request_Method,
  httpRequest.uri as URI,
  labels.0.name	as WAF_Rule,
  terminatingRuleId as WAF_RuleID
| sort @timestamp desc
| filter httpRequest.clientIp LIKE "34.234.200.15"
EOF
}

resource "aws_cloudwatch_query_definition" "filter_by_rule" {
  name = "WAF/Filter by Rule (${var.web_acl_name})"

  log_group_names = [aws_cloudwatch_log_group.waf.name]

  query_string = <<EOF
fields @timestamp as Timestamp,
  action as Action,
  terminatingRuleId as Rule,
  httpRequest.clientIp as Request_IP,
  httpRequest.country as Request_Country,
  httpRequest.httpMethod as Request_Method,
  httpRequest.uri as URI
| sort @timestamp desc
| filter action not like "ALLOW" and
| terminatingRuleId in ["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet", "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesLinuxRuleSet"]
EOF
}

resource "aws_cloudwatch_query_definition" "requests_by_country" {
  name = "WAF/Blocked Requests by Country (${var.web_acl_name})"

  log_group_names = [aws_cloudwatch_log_group.waf.name]

  query_string = <<EOF
fields httpRequest.country
| stats count(*) as requestCount by httpRequest.country
| sort requestCount desc
| limit 100
EOF
}
