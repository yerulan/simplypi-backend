from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class PendingRegistration(models.Model):
    first_name = models.CharField(max_length=100, unique=False)
    email = models.EmailField(unique=True)
    token = models.CharField(max_length=100, unique=True)
    stripe_customer_id = models.CharField(max_length=255)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

User.add_to_class('stripe_customer_id', models.CharField(max_length=255, null=True, blank=True))
