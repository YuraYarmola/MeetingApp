from cryptography.fernet import InvalidToken
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from drf_spectacular.utils import extend_schema, OpenApiResponse, inline_serializer
from rest_framework import generics, status, permissions, serializers
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import User
from .serializers import (UserSerializer, EmailSerializer,
                          ResetPasswordSerializer)


HOST = settings.HOST


class UserCreteListView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    @extend_schema(
        request=UserSerializer,
        responses={
            201: OpenApiResponse(
                response=inline_serializer(
                    name="UserCreateResponse",
                    fields={
                        "user": UserSerializer(),
                        "token": inline_serializer(
                            name="TokenResponse",
                            fields={
                                "access": serializers.CharField(
                                    help_text="JWT access token",
                                    default="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                ),
                                "refresh": serializers.CharField(
                                    help_text="JWT refresh token",
                                    default="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                )
                            }
                        ),
                    },
                    required=["user", "token"]
                )
            ),
            400: OpenApiResponse(
                description="Invalid input data"
            )
        },
        description="Create a new user and return user details along with an authentication token."

    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = UserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        token = RefreshToken.for_user(user)

        subject = 'MeetingApp password reset'
        message = f"""Dear {user.email},
                              Thank for registration"""

        recipient_list = [user.email]

        send_mail(subject, message, settings.EMAIL_HOST_USER, recipient_list)

        return Response({"user": serializer.data, "token": {"access": str(token.access_token), "refresh": str(token)}}, status=status.HTTP_201_CREATED)


class PasswordReset(APIView):
    """
    Request for Password Reset Link.
    """
    permission_classes = (AllowAny,)
    serializer_class = EmailSerializer

    def post(self, request):
        """
        Create token.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email_obj = serializer.data["email"]
        user = User.objects.filter(email=email_obj).first()
        if user:
            encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = reverse(
                "reset-password",
                kwargs={"encoded_pk": encoded_pk, "token": token},
            )
            reset_link = f"{HOST}{reset_url}"

            subject = 'MeetingApp password reset'
            message = f"""Dear {user.email},
                      You are receiving this email because a request to reset your password has been 
                      
                      If you did not make this request, please ignore this email.
                      To reset your password, click on the following link:
                      {reset_link}"""

            recipient_list = [user.email]

            send_mail(subject, message, settings.EMAIL_HOST_USER, recipient_list)

            return Response(
                {
                    "message":
                        f"Your password was sent"
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": "User doesn't exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPasswordCallback(APIView):
    """
    Verify and Reset Password Token View.
    """

    serializer_class = ResetPasswordSerializer
    permission_classes = (AllowAny,)

    def patch(self, request, *args, **kwargs):
        """
        Verify token & encoded_pk and then reset the password.
        """
        serializer = self.serializer_class(
            data=request.data, context={"kwargs": kwargs}
        )
        try:
            serializer.is_valid(raise_exception=True)
            return Response(
                {"message": "Password reset complete"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"message": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )



