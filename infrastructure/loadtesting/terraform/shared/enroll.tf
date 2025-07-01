resource "aws_secretsmanager_secret" "enroll_secret" {
  name       = "/mobius/loadtest/enroll/${random_pet.main.id}"
  kms_key_id = aws_kms_key.main.id
}
