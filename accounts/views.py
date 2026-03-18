import logging
import pyotp
import qrcode
import base64
import io
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
from .forms import LoginForm, RegistrationForm, TwoFactorForm, SetupTwoFactorForm
from .models import User

logger = logging.getLogger(__name__)

def register(request):
    if request.user.is_authenticated:
        return redirect('file_manager:dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            role = 'user'
            if not User.objects.exists():
                role = 'admin'
                messages.info(request, 'You have been registered as an admin user')

            try:
                user = User.objects.create_user(username=username, email=email, password=password, role=role)
                messages.success(request, 'Registration successful! You can now log in.')
                logger.info(f"New user registered: {user.username}")
                return redirect('accounts:login')
            except Exception as e:
                logger.error(f"Error registering user: {str(e)}")
                messages.error(request, 'An error occurred during registration')
    else:
        form = RegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('file_manager:dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)
            if user is not None:
                if user.is_2fa_enabled:
                    request.session['user_id_for_2fa'] = user.id
                    next_url = request.GET.get('next', '')
                    if next_url:
                        request.session['next_url'] = next_url
                    return redirect('accounts:verify_2fa')

                auth_login(request, user)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])

                logger.info(f"User logged in: {user.username}")
                messages.success(request, 'Login successful!')

                next_url = request.GET.get('next', '')
                if next_url:
                    return redirect(next_url)
                return redirect('file_manager:dashboard')
            else:
                messages.error(request, 'Invalid username or password')
                logger.warning(f"Failed login attempt for username: {username}")
    else:
        form = LoginForm()

    return render(request, 'accounts/login.html', {'form': form})

def verify_2fa(request):
    user_id = request.session.get('user_id_for_2fa')
    if not user_id:
        return redirect('accounts:login')

    if request.method == 'POST':
        form = TwoFactorForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                messages.error(request, 'User not found')
                return redirect('accounts:login')

            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp_code):
                request.session.pop('user_id_for_2fa', None)
                
                auth_login(request, user)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])

                logger.info(f"User completed 2FA: {user.username}")
                messages.success(request, 'Two-factor authentication successful!')

                next_url = request.session.pop('next_url', None)
                if next_url:
                    return redirect(next_url)
                return redirect('file_manager:dashboard')
            else:
                messages.error(request, 'Invalid verification code')
                logger.warning(f"Failed 2FA attempt for user ID: {user_id}")
    else:
        form = TwoFactorForm()

    return render(request, 'accounts/verify_2fa.html', {'form': form})

@login_required
def setup_2fa(request):
    user = request.user
    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        user.save(update_fields=['otp_secret'])

    totp = pyotp.TOTP(user.otp_secret)
    provisioning_url = totp.provisioning_uri(
        name=user.email,
        issuer_name="Secure File System"
    )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer)
    buffer.seek(0)

    qr_code_data = base64.b64encode(buffer.getvalue()).decode()

    if request.method == 'POST':
        form = SetupTwoFactorForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            if totp.verify(otp_code):
                user.is_2fa_enabled = True
                user.save(update_fields=['is_2fa_enabled'])
                
                logger.info(f"2FA enabled for user: {user.username}")
                messages.success(request, 'Two-factor authentication has been enabled!')
                return redirect('file_manager:dashboard')
            else:
                messages.error(request, 'Invalid verification code. Please try again.')
    else:
        form = SetupTwoFactorForm()

    return render(request, 'accounts/setup_2fa.html', {
        'form': form,
        'secret': user.otp_secret,
        'qr_code': qr_code_data
    })

@login_required
def disable_2fa(request):
    if request.method == 'POST':
        user = request.user
        if not user.is_2fa_enabled:
            messages.warning(request, 'Two-factor authentication is not enabled')
            return redirect('file_manager:dashboard')

        user.is_2fa_enabled = False
        user.save(update_fields=['is_2fa_enabled'])
        
        logger.info(f"2FA disabled for user: {user.username}")
        messages.success(request, 'Two-factor authentication has been disabled')
    
    return redirect('file_manager:dashboard')

@login_required
def logout_view(request):
    auth_logout(request)
    messages.info(request, 'You have been logged out')
    return redirect('accounts:login')
