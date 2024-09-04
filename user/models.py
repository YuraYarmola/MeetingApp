from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from .managers import CustomUserManager


class User(AbstractBaseUser):
    objects = CustomUserManager()
    email = models.EmailField(unique=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)

    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    @staticmethod
    def create_or_return(email: str) -> tuple['User', bool]:
        user = User.objects.filter(email=email)
        user_created = False
        if user:
            user = user.first()
        else:
            user = User(email=email)
            user.save()
            user_created = True

        return user, user_created
