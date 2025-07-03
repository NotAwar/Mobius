resource "aws_ecs_cluster" "mobius" {
  name = "${local.prefix}-backend"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_service" "mobius" {
  name                               = "mobius"
  launch_type                        = "FARGATE"
  cluster                            = aws_ecs_cluster.mobius.id
  task_definition                    = aws_ecs_task_definition.backend.arn
  desired_count                      = var.mobius_containers
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 30

  load_balancer {
    target_group_arn = aws_lb_target_group.internal.arn
    container_name   = "mobius"
    container_port   = 8080
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.main.arn
    container_name   = "mobius"
    container_port   = 8080
  }

  network_configuration {
    subnets         = data.terraform_remote_state.shared.outputs.vpc.private_subnets
    security_groups = [aws_security_group.backend.id]
  }
}

resource "aws_cloudwatch_log_group" "backend" { #tfsec:ignore:aws-cloudwatch-log-group-customer-key
  name              = local.prefix
  retention_in_days = 1
}

data "aws_secretsmanager_secret" "license" {
  name = "/mobius/license"
}

resource "aws_ecs_task_definition" "backend" {
  family                   = local.prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.main.arn
  task_role_arn            = aws_iam_role.main.arn
  cpu                      = 1024
  memory                   = 4096
  container_definitions = jsonencode(
    [
      {
        name      = "prometheus-exporter"
        image     = "${data.terraform_remote_state.shared.outputs.ecr.repository_url}:latest"
        essential = false
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.backend.name
            awslogs-region        = data.aws_region.current.name
            awslogs-stream-prefix = "mobius-prometheus-exporter"
          }
        }
        environment = [
          {
            name  = "CLOUDWATCH_NAMESPACE"
            value = "mobius-loadtest"
          },
          {
            name  = "CLOUDWATCH_REGION"
            value = "us-east-2"
          },
          {
            name  = "PROMETHEUS_SCRAPE_URL"
            value = "http://localhost:8080/metrics"
          },
        ],
      },
      {
        name        = "mobius"
        image       = docker_registry_image.mobius.name
        cpu         = 1024
        memory      = 4096
        mountPoints = []
        volumesFrom = []
        essential   = true
        portMappings = [
          {
            # This port is the same that the contained application also uses
            containerPort = 8080
            hostPort      = 8080
            protocol      = "tcp"
          }
        ]
        ulimits = [
          {
            softLimit = 9999,
            hardLimit = 9999,
            name      = "nofile"
          }
        ]
        networkMode = "awsvpc"
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.backend.name
            awslogs-region        = data.aws_region.current.name
            awslogs-stream-prefix = "mobius"
          }
        },
        secrets = [
          {
            name      = "MOBIUS_MYSQL_PASSWORD"
            valueFrom = aws_secretsmanager_secret.database_password_secret.arn
          },
          {
            name      = "MOBIUS_MYSQL_READ_REPLICA_PASSWORD"
            valueFrom = aws_secretsmanager_secret.database_password_secret.arn
          },
          {
            name      = "MOBIUS_LICENSE_KEY"
            valueFrom = data.aws_secretsmanager_secret.license.arn
          },
          {
            name      = "MOBIUS_SERVER_PRIVATE_KEY"
            valueFrom = aws_secretsmanager_secret.mobius_server_private_key.arn
          }
        ]
        environment = concat([
          {
            name  = "MOBIUS_LOGGING_JSON"
            value = "true"
          },
          {
            name  = "MOBIUS_MYSQL_USERNAME"
            value = module.aurora_mysql.cluster_master_username
          },
          {
            name  = "MOBIUS_MYSQL_DATABASE"
            value = module.aurora_mysql.cluster_database_name
          },
          {
            name  = "MOBIUS_MYSQL_ADDRESS"
            value = "${module.aurora_mysql.cluster_endpoint}:3306"
          },
          {
            name  = "MOBIUS_MYSQL_MAX_OPEN_CONNS"
            value = "10"
          },
          {
            name  = "MOBIUS_MYSQL_READ_REPLICA_USERNAME"
            value = module.aurora_mysql.cluster_master_username
          },
          {
            name  = "MOBIUS_MYSQL_READ_REPLICA_DATABASE"
            value = module.aurora_mysql.cluster_database_name
          },
          {
            name  = "MOBIUS_MYSQL_READ_REPLICA_ADDRESS"
            value = "${module.aurora_mysql.cluster_reader_endpoint}:3306"
          },
          {
            name  = "MOBIUS_MYSQL_READ_REPLICA_MAX_OPEN_CONNS"
            value = "10"
          },
          {
            name  = "MOBIUS_REDIS_ADDRESS"
            value = "${aws_elasticache_replication_group.default.primary_endpoint_address}:6379"
          },
          {
            name  = "MOBIUS_REDIS_CLUSTER_FOLLOW_REDIRECTIONS"
            value = "true"
          },
          {
            name  = "MOBIUS_OSQUERY_STATUS_LOG_PLUGIN"
            value = "filesystem"
          },
          {
            name  = "MOBIUS_FILESYSTEM_STATUS_LOG_FILE"
            value = "/dev/null"
          },
          {
            name  = "MOBIUS_OSQUERY_RESULT_LOG_PLUGIN"
            value = "filesystem"
          },
          {
            name  = "MOBIUS_FILESYSTEM_RESULT_LOG_FILE"
            value = "/dev/null"
          },
          {
            name  = "MOBIUS_SERVER_TLS"
            value = "false"
          },
          {
            name  = "MOBIUS_REDIS_MAX_IDLE_CONNS"
            value = "100"
          },
          {
            name  = "MOBIUS_REDIS_MAX_OPEN_CONNS"
            value = "100"
          },
          {
            name  = "MOBIUS_OSQUERY_ASYNC_HOST_REDIS_SCAN_KEYS_COUNT"
            value = "10000"
          },
          {
            name  = "MOBIUS_S3_SOFTWARE_INSTALLERS_BUCKET"
            value = aws_s3_bucket.software_installers.bucket
          },
        ], local.additional_env_vars)
      }
  ])
  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_ecs_task_definition" "migration" {
  family                   = "${local.prefix}-migrate"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.main.arn
  task_role_arn            = aws_iam_role.main.arn
  cpu                      = 1024
  memory                   = 2048
  container_definitions = jsonencode(
    [
      {
        name        = "mobius-prepare-db"
        image       = docker_registry_image.mobius.name
        cpu         = 1024
        memory      = 2048
        mountPoints = []
        volumesFrom = []
        essential   = true
        portMappings = [
          {
            # This port is the same that the contained application also uses
            containerPort = 8080
            protocol      = "tcp"
          }
        ]
        networkMode = "awsvpc"
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            awslogs-group         = aws_cloudwatch_log_group.backend.name
            awslogs-region        = data.aws_region.current.name
            awslogs-stream-prefix = "mobius-migration"
          }
        },
        command = ["mobius", "prepare", "--no-prompt=true", "db"]
        secrets = [
          {
            name      = "MOBIUS_MYSQL_PASSWORD"
            valueFrom = aws_secretsmanager_secret.database_password_secret.arn
          }
        ]
        environment = [
          {
            name  = "CLOUDWATCH_NAMESPACE"
            value = "mobius-loadtest-migration"
          },
          {
            name  = "CLOUDWATCH_REGION"
            value = "us-east-2"
          },
          {
            name  = "MOBIUS_MYSQL_USERNAME"
            value = module.aurora_mysql.cluster_master_username
          },
          {
            name  = "MOBIUS_MYSQL_DATABASE"
            value = module.aurora_mysql.cluster_database_name
          },
          {
            name  = "MOBIUS_MYSQL_ADDRESS"
            value = "${module.aurora_mysql.cluster_endpoint}:3306"
          },
          {
            name  = "MOBIUS_REDIS_ADDRESS"
            value = "${aws_elasticache_replication_group.default.primary_endpoint_address}:6379"
          },
        ]
      }
  ])
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = var.mobius_containers
  min_capacity       = var.mobius_containers
  resource_id        = "service/${aws_ecs_cluster.mobius.name}/${aws_ecs_service.mobius.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_policy_memory" {
  name               = "${local.prefix}-memory-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value = 80
  }
}

resource "aws_appautoscaling_policy" "ecs_policy_cpu" {
  name               = "${local.prefix}-cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    target_value = 90
  }
}

resource "random_password" "mobius_server_private_key" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "mobius_server_private_key" {
  name = "${terraform.workspace}-mobius-server-private-key"

  recovery_window_in_days = "0"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_secretsmanager_secret_version" "mobius_server_private_key" {
  secret_id     = aws_secretsmanager_secret.mobius_server_private_key.id
  secret_string = random_password.mobius_server_private_key.result
}
