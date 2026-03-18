from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
import re

User = get_user_model()

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    remember = forms.BooleanField(required=False, label='Remember Me', widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))


class RegistrationForm(forms.Form):
    username = forms.CharField(max_length=64, min_length=3, widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(min_length=8, widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', 'Passwords must match')
            
        return cleaned_data

    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password:
            if not re.search(r"[A-Z]", password):
                raise ValidationError("Password must contain at least one uppercase letter")
            if not re.search(r"[a-z]", password):
                raise ValidationError("Password must contain at least one lowercase letter")
            if not re.search(r"[0-9]", password):
                raise ValidationError("Password must contain at least one number")
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                raise ValidationError("Password must contain at least one special character")
        return password

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("Username already exists")
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("Email already exists")
        return email


class TwoFactorForm(forms.Form):
    otp_code = forms.CharField(max_length=6, min_length=6, widget=forms.TextInput(attrs={'class': 'form-control'}))


class SetupTwoFactorForm(forms.Form):
    otp_code = forms.CharField(max_length=6, min_length=6, widget=forms.TextInput(attrs={'class': 'form-control'}))
