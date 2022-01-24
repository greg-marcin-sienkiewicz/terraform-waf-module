# terraform-waf-module

The module utilizes git Tags to denote release with Semantic versioning. Each release is prefixed with the letter v.

Please refer to the release history to determine the version, and update the source in the module accordingly.

```
module "name" {
  source = "github.com/greg-marcin-sienkiewicz/terraform-waf-module?ref=v1.0.0"

  alb_arn            = var.alb_arn
  managed_rules      = var.managed_rules
  waf_log_group_name = var.waf_log_group_name
  web_acl_name       = var.web_acl_name
  retention_in_days  = var.retention_in_days
  tags               = var.tags
}
```
