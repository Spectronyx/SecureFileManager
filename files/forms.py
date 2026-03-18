from django import forms
from django.core.validators import FileExtensionValidator

class FileUploadForm(forms.Form):
    file = forms.FileField(
        validators=[FileExtensionValidator(allowed_extensions=['txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'])],
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'})
    )
    notes = forms.CharField(max_length=500, required=False, widget=forms.Textarea(attrs={'class': 'form-control'}))


class FileShareForm(forms.Form):
    PERMISSION_CHOICES = (
        ('read', 'Read Only'),
        ('edit', 'Read & Edit'),
    )
    username = forms.CharField(max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    permissions = forms.ChoiceField(choices=PERMISSION_CHOICES, widget=forms.Select(attrs={'class': 'form-select'}))


class SearchForm(forms.Form):
    query = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))


class DeleteFileForm(forms.Form):
    confirm = forms.CharField(initial='yes', widget=forms.HiddenInput())
