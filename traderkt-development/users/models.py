from django.contrib.auth.models import AbstractUser, Group
from django.db import models
from django.conf import settings
from django.core.validators import validate_comma_separated_integer_list


class TraderKitUser(AbstractUser):
    pass


USER_TYPE_CHOICES = (
    ('A', 'Admin'),
    ('C', 'Customer'),
    ('U', 'Users'),
)


class UserProfile(models.Model):
    user = models.OneToOneField(TraderKitUser, related_name='profile', on_delete=models.CASCADE)
    user_type = models.CharField(max_length=5, choices=USER_TYPE_CHOICES)
    mobile = models.BigIntegerField(null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='created_by', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    role_id = models.CharField(max_length=100, validators=[validate_comma_separated_integer_list], null=True)


class Roles(models.Model):
    group = models.OneToOneField(Group, related_name='details', on_delete=models.CASCADE)
    alias = models.CharField(max_length=50)
    accesses = models.TextField(null=True)
    description = models.TextField(null=True)
    created_by = models.ForeignKey(TraderKitUser, to_field='id', null=True, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


class PasswordResetTokens(models.Model):
    user = models.ForeignKey(TraderKitUser, related_name="+", on_delete=models.CASCADE)
    token = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
