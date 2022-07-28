from os import link
from django.core.exceptions import ValidationError
from rest_framework import serializers
from Auth.accounts.utils import Util
from .models import MyUser
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator





class MyUserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = MyUser
        fields = ['email', 'name', 'password', 'password2','tc']
        extra_kwargs = {
            'password': {'write_only': True}
        }
        def validate(self, attrs):
            password = attrs.get('password')
            password2 = attrs.get('password2')
            if password != password2:
                raise serializers.ValidationError("Passwords do not match")
            return attrs


    def create(self, validate_data):
        return MyUser.objects.create_user(**validate_data)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = MyUser
        fields = ['email', 'password']


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('id', 'email', 'name')

class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style= {'input_type':'password'}, write_only= True)
    password2 = serializers.CharField(max_length = 255, style= {'input_type':'password'}, write_only= True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length =255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if MyUser.objects.filter(email=email).exists():
            user = MyUser.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID:', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password reset token:', token)
            link = 'http://localhost:3000/api/user/reset/' + uid +'/'+token
            print("link: ",link)
            body = 'Click link to reset password' + link
            data = {'subject':'Reset password', 'body':body}
            Util.send_email(data)
            return attrs
        else:
            raise ValidationError('Not a registered user')


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style= {'input_type':'password'}, write_only= True)
    password2 = serializers.CharField(max_length = 255, style= {'input_type':'password'}, write_only= True)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Passwords do not match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = MyUser.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not valid or has expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Invalid Token')
