from django.urls import path
from . import views

app_name = 'file_manager'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('upload/', views.upload_file, name='upload'),
    path('file/<int:file_id>/', views.file_details, name='file_details'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),
    path('share/<int:file_id>/', views.share_file, name='share_file'),
    path('unshare/<int:file_id>/<int:user_id>/', views.unshare_file, name='unshare_file'),
    path('delete/<int:file_id>/', views.delete_file, name='delete_file'),
    path('search/', views.search, name='search'),
    path('admin/', views.admin_dashboard, name='admin_dashboard'),
]
