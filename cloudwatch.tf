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
}

resource "aws_kms_alias" "cloudwatch_waf" {
  name          = "alias/aws-waf-logs-${var.waf_log_group_name}-key"
  target_key_id = aws_kms_key.cloudwatch_waf.key_id
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.waf_log_group_name}"
  retention_in_days = var.retention_in_days
  kms_key_id        = aws_kms_key.cloudwatch_waf.arn
}