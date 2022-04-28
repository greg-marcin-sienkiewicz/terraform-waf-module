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
| filter httpRequest.clientIp LIKE "127.0.0.1"
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

###=============== CloudWatch Dashboard   =============== ###

resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "${var.web_acl_name}-waf"

  dashboard_body = <<EOF
{
    "widgets": [
        {
            "height": 6,
            "width": 24,
            "y": 16,
            "x": 0,
            "type": "metric",
            "properties": {
                "stat": "Sum",
                "view": "singleValue",
                "stacked": true,
                "metrics": [
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesAmazonIpReputationList", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesCommonRuleSet", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesLinuxRuleSet", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesUnixRuleSet", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesSQLiRuleSet", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "AWSManagedRulesKnownBadInputsRuleSet", "WebACL", "${var.web_acl_name}" ]
                ],
                "region": "us-east-1",
                "title": "WAF Rule BlockedRequests",
                "yAxis": {
                    "left": {
                        "showUnits": false
                    },
                    "right": {
                        "showUnits": false
                    }
                },
                "period": 300,
                "setPeriodToTimeRange": true
            }
        },
        {
            "height": 8,
            "width": 6,
            "y": 0,
            "x": 18,
            "type": "log",
            "properties": {
                "query": "SOURCE 'aws-waf-logs-${var.waf_log_group_name}' | fields httpRequest.country\n| stats count(*) as requestCount by httpRequest.country\n| sort requestCount desc\n| limit 10",
                "region": "us-east-1",
                "stacked": false,
                "title": "Top 10 by Country",
                "view": "pie"
            }
        },
        {
            "height": 8,
            "width": 6,
            "y": 0,
            "x": 0,
            "type": "log",
            "properties": {
                "query": "SOURCE 'aws-waf-logs-${var.waf_log_group_name}' | fields terminatingRuleId\n| stats count(*) as requestCount by terminatingRuleId\n| filter terminatingRuleId not like \"Default_Action\"\n| sort requestCount desc\n| limit 10",
                "region": "us-east-1",
                "stacked": false,
                "title": "Top 10 by Rule",
                "view": "pie"
            }
        },
        {
            "height": 8,
            "width": 6,
            "y": 0,
            "x": 6,
            "type": "log",
            "properties": {
                "query": "SOURCE 'aws-waf-logs-${var.waf_log_group_name}' | fields httpRequest.clientIp\n| stats count(*) as requestCount by httpRequest.clientIp\n| sort requestCount desc\n| limit 10",
                "region": "us-east-1",
                "stacked": false,
                "title": "Top 10 by IP Address",
                "view": "pie"
            }
        },
        {
            "height": 8,
            "width": 24,
            "y": 8,
            "x": 0,
            "type": "metric",
            "properties": {
                "stat": "Sum",
                "view": "timeSeries",
                "stacked": true,
                "metrics": [
                    [ "AWS/WAFV2", "AllowedRequests", "Region", "us-east-1", "Rule", "${var.web_acl_name}", "WebACL", "${var.web_acl_name}" ],
                    [ "AWS/WAFV2", "BlockedRequests", "Region", "us-east-1", "Rule", "${var.web_acl_name}", "WebACL", "${var.web_acl_name}" ]
                ],
                "region": "us-east-1",
                "title": "WAF Activity",
                "yAxis": {
                    "left": {
                        "showUnits": false
                    },
                    "right": {
                        "showUnits": false
                    }
                },
                "period": 300,
                "setPeriodToTimeRange": true
            }
        },
        {
            "height": 8,
            "width": 6,
            "y": 0,
            "x": 12,
            "type": "log",
            "properties": {
                "query": "SOURCE 'aws-waf-logs-${var.waf_log_group_name}' | fields httpRequest.clientIp\n| stats count(*) as requestCount by httpRequest.clientIp\n| filter terminatingRuleId like \"AWSManagedRulesAmazonIpReputationList\"\n| sort requestCount desc\n| limit 10",
                "region": "us-east-1",
                "stacked": false,
                "title": "Top 10 by AWSManagedRulesAmazonIpReputationList",
                "view": "pie"
            }
        }
    ]
}
EOF
}
