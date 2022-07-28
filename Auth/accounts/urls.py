from django.urls import path
from .views import  LoginView, PasswordResetView, ProfileView, SendPasswordRestEmailView, UserRegistrationView, ChangePasswordView


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name= 'register'),
    path('login/', LoginView.as_view(), name= 'login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('changepassword/', ChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordRestEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', PasswordResetView.as_view(), name='reset-password'),

]
