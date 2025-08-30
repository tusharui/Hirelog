from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    ROLE_CHOICES =(
        ("candidate", "Candidate"),
        ("recruiter","Recruiter"),
        ('user', 'User'),
        ("admin", "Admin"),


    )

    role = models.CharField(max_length = 10 , choices = ROLE_CHOICES)
    def __str__(self):
        return f"{self.username} ({self.role})"
    
