from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

def index(request):
    return redirect('accounts:login')

urlpatterns = [
    path('', index, name='index'),
    path('django-admin/', admin.site.urls),
    path('auth/', include('accounts.urls')),
    path('files/', include('files.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
