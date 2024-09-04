from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import transaction
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        with transaction.atomic():
            password = validated_data.pop('password')
            user = User(**validated_data)
            validate_password(password)
            user.set_password(password)
            user.save()
            return user

    def validate(self, data):
        validate_password(data['password'])
        return data


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ("email",)


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        min_length=1,
    )

    class Meta:
        field = ("password",)

    def validate(self, data):
        """
        Verify token and encoded_pk and then set new password.
        """
        password = data.get("password")
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data.")

        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The reset token is invalid")
        validate_password(password)
        user.set_password(password)
        user.save()
        return data

