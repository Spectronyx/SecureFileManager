from django.db import models
from django.conf import settings

class File(models.Model):
    filename = models.CharField(max_length=255)
    original_filename = models.CharField(max_length=255)
    encrypted_path = models.CharField(max_length=255)
    file_size = models.IntegerField()
    file_type = models.CharField(max_length=50)
    iv = models.CharField(max_length=100)  # Base64 encoded IV
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files')
    upload_date = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    is_malware_scanned = models.BooleanField(default=False)
    is_malware_detected = models.BooleanField(default=False)

    def __str__(self):
        return f'<File {self.original_filename}>'

class FileShare(models.Model):
    PERMISSION_CHOICES = (
        ('read', 'Read Only'),
        ('edit', 'Read & Edit'),
    )
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shares')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_files_received')
    shared_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_shares')
    permissions = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='read')
    shared_date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('file', 'user')

    def __str__(self):
        return f'<FileShare {self.file.id} shared with {self.user.id}>'

class AccessLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='access_logs')
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='access_logs')
    action = models.CharField(max_length=20)  # upload, download, view, edit, share, delete
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return f'<AccessLog {self.action} on {self.file.id} by {self.user.id}>'
