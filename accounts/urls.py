from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('disable-2fa/', views.disable_2fa, name='disable_2fa'),
    path('logout/', views.logout_view, name='logout'),
]
