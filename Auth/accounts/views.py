from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import ChangePasswordSerializer, LoginSerializer, MyUserRegistrationSerializer, PasswordResetSerializer, ProfileSerializer, SendPasswordResetEmailSerializer
from rest_framework.permissions import IsAuthenticated


#generate tokens manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = MyUserRegistrationSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token =get_tokens_for_user(user)
        return Response({'token':token, 'msg': 'Registeration success'}, status = status.HTTP_201_CREATED)

class LoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class ProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = ProfileSerializer(request.user)
    print(serializer)
    return Response(serializer.data, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data= request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password Changed'}, status = status.HTTP_201_CREATED)

class SendPasswordRestEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data= request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password reset link sent. Link is valid for 15 mins only'}, status = status.HTTP_201_CREATED)


class PasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request,uid, token, format=None):
        serializer = PasswordResetSerializer(data = request.data, context={'uid':uid,'token':token})
        serializer.is_valid(raise_exception=True)
        return Response({'msg': 'Password reset successfully'}, status = status.HTTP_201_CREATED)
