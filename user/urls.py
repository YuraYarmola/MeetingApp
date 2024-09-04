from django.urls import path
from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    # JWT AUTH
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("reset_password/", PasswordReset.as_view(), name="request-password-reset"),
    path("password-reset/<str:encoded_pk>/<str:token>/", ResetPasswordCallback.as_view(), name="reset-password"),

    # Registration
    path("register/", UserCreteListView.as_view(), name="user"),

]
