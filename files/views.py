import os
import uuid
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import FileResponse, Http404
from django.conf import settings
from django.utils import timezone
from .models import File, FileShare, AccessLog
from accounts.models import User
from .forms import FileUploadForm, FileShareForm, SearchForm, DeleteFileForm
from .security import encrypt_file, decrypt_file
from .malware_detection import scan_file_for_malware

logger = logging.getLogger(__name__)

def log_file_access(request, file_id, action):
    """Record an access to a file in the access log"""
    # Defensive check against passing None for user (even if not possible with @login_required)
    if not request.user.is_authenticated:
        return
        
    try:
        user = request.user
        file_obj = File.objects.get(id=file_id)
        AccessLog.objects.create(
            user=user,
            file=file_obj,
            action=action,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        logger.info(f"File access logged: {action} on file {file_id} by user {user.id}")
    except Exception as e:
        logger.error(f"Failed to log access for file {file_id}: {str(e)}")

@login_required
def dashboard(request):
    my_files = File.objects.filter(user=request.user).order_by('-upload_date')
    
    # Get files explicitly shared with the user
    shared_files_qs = File.objects.filter(shares__user=request.user).order_by('-upload_date')
    
    search_form = SearchForm()
    
    return render(request, 'files/dashboard.html', {
        'my_files': my_files,
        'shared_files': shared_files_qs,
        'search_form': search_form
    })

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            
            # Generate secure name
            original_filename = uploaded_file.name
            file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            secure_filename_with_uuid = f"{uuid.uuid4().hex}.{file_extension}"
            
            # Ensure upload paths exist
            upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
            encrypted_dir = os.path.join(settings.MEDIA_ROOT, 'encrypted')
            os.makedirs(upload_dir, exist_ok=True)
            os.makedirs(encrypted_dir, exist_ok=True)
            
            temp_path = os.path.join(upload_dir, secure_filename_with_uuid)
            
            # Save temporary file using chunks to avoid memory exhaustion
            with open(temp_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            file_size = os.path.getsize(temp_path)
            
            # Check file size against a configurable MAX limit (16MB max)
            max_size = getattr(settings, 'MAX_UPLOAD_SIZE', 16 * 1024 * 1024)
            if file_size > max_size:
                os.remove(temp_path)
                messages.error(request, 'File is too large')
                return redirect('file_manager:upload')
            
            is_malware = scan_file_for_malware(temp_path)
            
            try:
                encrypted_path, iv = encrypt_file(temp_path, encrypted_dir)
                os.remove(temp_path)
                
                new_file = File.objects.create(
                    filename=secure_filename_with_uuid,
                    original_filename=original_filename,
                    encrypted_path=encrypted_path,
                    file_size=file_size,
                    file_type=file_extension,
                    iv=iv,
                    user=request.user,
                    is_malware_scanned=True,
                    is_malware_detected=is_malware
                )
                
                log_file_access(request, new_file.id, 'upload')
                
                if is_malware:
                    messages.warning(request, 'File uploaded but malware detected! File has been quarantined.')
                else:
                    messages.success(request, 'File uploaded successfully!')
                    
                logger.info(f"File uploaded: {original_filename} by user {request.user.id}")
                return redirect('file_manager:dashboard')
                
            except Exception as e:
                logger.error(f"Error during file upload: {str(e)}")
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                messages.error(request, 'An error occurred during file upload')
                return redirect('file_manager:upload')
    else:
        form = FileUploadForm()
        
    return render(request, 'files/file_upload.html', {'form': form})

@login_required
def file_details(request, file_id):
    file_obj = get_object_or_404(File, id=file_id)
    
    is_owner = file_obj.user == request.user
    share = None
    if not is_owner:
        share = FileShare.objects.filter(file=file_obj, user=request.user).first()
        if not share:
            logger.warning(f"Unauthorized access attempt to file {file_id} by user {request.user.id}")
            raise Http404
            
    shared_with = []
    if is_owner:
        shared_with = User.objects.filter(shared_files_received__file=file_obj)
        
    file_obj.last_accessed = timezone.now()
    file_obj.save(update_fields=['last_accessed'])
    
    log_file_access(request, file_obj.id, 'view')
    
    share_form = FileShareForm() if is_owner else None
    delete_form = DeleteFileForm() if is_owner else None
    
    return render(request, 'files/file_details.html', {
        'file': file_obj,
        'is_owner': is_owner,
        'share': share,
        'shared_with': shared_with,
        'share_form': share_form,
        'delete_form': delete_form
    })

@login_required
def download_file(request, file_id):
    file_obj = get_object_or_404(File, id=file_id)
    
    is_owner = file_obj.user == request.user
    share = None
    if not is_owner:
        share = FileShare.objects.filter(file=file_obj, user=request.user).first()
        if not share:
            logger.warning(f"Unauthorized download attempt of file {file_id} by user {request.user.id}")
            raise Http404
            
    if file_obj.is_malware_detected:
        messages.error(request, 'This file has been flagged as potentially malicious and cannot be downloaded')
        return redirect('file_manager:file_details', file_id=file_obj.id)
        
    upload_dir = os.path.join(settings.MEDIA_ROOT, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, f"temp_{uuid.uuid4().hex}")
    
    try:
        log_file_access(request, file_obj.id, 'download')
        
        decrypt_file(file_obj.encrypted_path, temp_path, file_obj.iv)
        
        file_obj.last_accessed = timezone.now()
        file_obj.save(update_fields=['last_accessed'])
        
        # Open file to return via FileResponse.
        # FileResponse takes care of closing it. 
        # But we need to clean up `temp_path` afterward, which is tricky in Django without middleware/generators.
        # To mimic Flask's `call_on_close`, we wrap the file in a generator that yields chunks and deletes the file at the end.
        
        def file_iterator(file_path, chunk_size=8192):
            try:
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk
            finally:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        logger.debug(f"Temporary file {file_path} removed")
                    except Exception as e:
                        logger.error(f"Failed to remove temp file {file_path}: {e}")

        response = FileResponse(file_iterator(temp_path), as_attachment=True, filename=file_obj.original_filename)
        return response
        
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
                
        error_message = str(e)
        logger.error(f"Error during file download: {error_message}")
        if "Padding is incorrect" in error_message or "MAC check failed" in error_message:
            messages.error(request, 'Unable to decrypt this file. Encryption key mismatch.')
        else:
            messages.error(request, 'An error occurred during file download')
            
        return redirect('file_manager:file_details', file_id=file_obj.id)

@login_required
def share_file(request, file_id):
    file_obj = get_object_or_404(File, id=file_id)
    
    if file_obj.user != request.user:
        logger.warning(f"Unauthorized sharing attempt of file {file_id} by user {request.user.id}")
        raise Http404
        
    if request.method == 'POST':
        form = FileShareForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            permissions = form.cleaned_data['permissions']
            
            user_to_share_with = User.objects.filter(username=username).first()
            if not user_to_share_with:
                messages.error(request, f'User {username} not found')
                return redirect('file_manager:file_details', file_id=file_id)
                
            if user_to_share_with == request.user:
                messages.error(request, 'You cannot share a file with yourself')
                return redirect('file_manager:file_details', file_id=file_id)
                
            share, created = FileShare.objects.update_or_create(
                file=file_obj,
                user=user_to_share_with,
                defaults={'shared_by': request.user, 'permissions': permissions}
            )
            
            action_msg = 'Shared' if created else 'Updated sharing permissions for'
            messages.success(request, f'{action_msg} file with {username}')
            
            log_file_access(request, file_id, 'share')
            logger.info(f"File {file_id} shared with user {user_to_share_with.id} by {request.user.id}")
            
    return redirect('file_manager:file_details', file_id=file_id)

@login_required
def unshare_file(request, file_id, user_id):
    if request.method == 'POST':
        file_obj = get_object_or_404(File, id=file_id)
        
        if file_obj.user != request.user:
            logger.warning(f"Unauthorized unsharing attempt of file {file_id} by user {request.user.id}")
            raise Http404
            
        share = FileShare.objects.filter(file_id=file_id, user_id=user_id).first()
        if not share:
            messages.error(request, 'Share not found')
            return redirect('file_manager:file_details', file_id=file_id)
            
        username = share.user.username
        share.delete()
        
        messages.success(request, f'File no longer shared with {username}')
        logger.info(f"File {file_id} unshared from user {user_id} by {request.user.id}")
        
    return redirect('file_manager:file_details', file_id=file_id)

@login_required
def delete_file(request, file_id):
    if request.method == 'POST':
        file_obj = get_object_or_404(File, id=file_id)
        
        if file_obj.user != request.user:
            logger.warning(f"Unauthorized delete attempt of file {file_id} by user {request.user.id}")
            raise Http404
            
        form = DeleteFileForm(request.POST)
        if form.is_valid():
            encrypted_path = file_obj.encrypted_path
            
            log_file_access(request, file_obj.id, 'delete')
            
            file_obj.delete()
            
            try:
                if os.path.exists(encrypted_path):
                    os.remove(encrypted_path)
            except Exception as e:
                logger.error(f"Error deleting encrypted file: {str(e)}")
                
            messages.success(request, 'File deleted successfully')
            logger.info(f"File {file_id} deleted by user {request.user.id}")
            
    return redirect('file_manager:dashboard')

@login_required
def search(request):
    query = request.GET.get('query') or (request.POST.get('query') if request.method == 'POST' else None)
    results = []
    
    if query:
        own_files = File.objects.filter(user=request.user, original_filename__icontains=query)
        shared_files = File.objects.filter(shares__user=request.user, original_filename__icontains=query)
        
        # Combine and remove duplicates (though theoretically no dupes here due to how ownership vs sharing works)
        all_files = list(own_files) + list(shared_files)
        seen = set()
        for f in all_files:
            if f.id not in seen:
                results.append(f)
                seen.add(f.id)
                
        if not results:
            messages.info(request, 'No files found matching your search')
            
    form = SearchForm(initial={'query': query})
    
    return render(request, 'files/dashboard.html', {
        'search_results': True, # Signal that this is a search view
        'my_files': results, # In search view, we combine them into one list conceptually
        'search_query': query,
        'search_form': form
    })

@login_required
def admin_dashboard(request):
    if request.user.role != 'admin':
        logger.warning(f"Non-admin user {request.user.id} attempted to access admin dashboard")
        raise Http404
        
    users = User.objects.all()
    files = File.objects.all()
    logs = AccessLog.objects.order_by('-timestamp')[:100]
    
    return render(request, 'files/admin.html', {
        'users': users,
        'files': files,
        'logs': logs
    })
