output "private_subnets" {
  value = data.terraform_remote_state.shared.outputs.vpc.private_subnet_arns
}

output "mobius_migration_revision" {
  value = aws_ecs_task_definition.migration.revision
}

output "mobius_migration_subnets" {
  value = jsonencode(aws_ecs_service.mobius.network_configuration[0].subnets)
}

output "mobius_migration_security_groups" {
  value = jsonencode(aws_ecs_service.mobius.network_configuration[0].security_groups)
}

output "mobius_ecs_cluster_arn" {
  value = aws_ecs_cluster.mobius.arn
}

output "mobius_ecs_cluster_id" {
  value = aws_ecs_cluster.mobius.id
}
