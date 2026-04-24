from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .models import SystemBackup, SystemBackupSchedule
from .system_backup_services import (
    create_system_backup,
    get_or_create_primary_schedule,
    restore_system_backup,
    run_due_system_backups,
)


def _can_manage_system_backups(user):
    return (
        user.is_superuser
        or user.has_perm('core.view_databasefile')
        or user.has_perm('core.add_databasefile')
        or user.has_perm('core.change_databasefile')
        or user.has_perm('core.delete_databasefile')
    )


def _permission_denied_response(request, message='You do not have permission to perform this action.'):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'ok': False, 'message': message}, status=403)

    messages.error(request, message, extra_tags='permission-modal')
    referer = (request.META.get('HTTP_REFERER') or '').strip()
    if referer and url_has_allowed_host_and_scheme(referer, {request.get_host()}):
        return redirect(referer)
    return redirect('dashboard')


def _parse_boolean_field(post_data, key):
    return post_data.get(key) in {'1', 'true', 'on', 'yes'}


def _format_file_size(size_bytes):
    units = ['B', 'KB', 'MB', 'GB']
    value = float(max(0, int(size_bytes or 0)))
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024.0
        index += 1
    if index == 0:
        return f'{int(value)} {units[index]}'
    return f'{value:.2f} {units[index]}'


@login_required
def system_hub(request):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to manage system backups.')

    run_due_system_backups()
    schedule = get_or_create_primary_schedule(updated_by=request.user)

    if request.method == 'POST':
        schedule.name = (request.POST.get('name') or '').strip() or 'Primary Backup Schedule'
        schedule.is_enabled = _parse_boolean_field(request.POST, 'is_enabled')
        schedule.job_type = (request.POST.get('job_type') or 'backup_cleanup').strip()

        raw_cron_minute = (request.POST.get('cron_minute') or '0').strip()
        raw_max_backups = (request.POST.get('max_backups') or '10').strip()

        try:
            schedule.cron_minute = int(raw_cron_minute)
        except (TypeError, ValueError):
            schedule.cron_minute = 0

        try:
            schedule.max_backups = int(raw_max_backups)
        except (TypeError, ValueError):
            schedule.max_backups = 10

        schedule.include_logs = _parse_boolean_field(request.POST, 'include_logs')
        schedule.include_docs = _parse_boolean_field(request.POST, 'include_docs')
        schedule.include_media = _parse_boolean_field(request.POST, 'include_media')
        schedule.include_database = _parse_boolean_field(request.POST, 'include_database')
        schedule.include_static = _parse_boolean_field(request.POST, 'include_static')
        schedule.include_templates = _parse_boolean_field(request.POST, 'include_templates')
        schedule.updated_by = request.user

        try:
            schedule.full_clean()
            schedule.save()
            messages.success(request, 'System backup schedule updated successfully.')
        except Exception as exc:
            messages.error(request, f'Unable to update schedule: {exc}')

        return redirect('system_hub')

    backups_queryset = SystemBackup.objects.select_related('created_by').order_by('-created_at')
    backups_page = Paginator(backups_queryset, 12).get_page(request.GET.get('page'))

    selected_scopes = [
        scope for scope, enabled in [
            ('logs', schedule.include_logs),
            ('docs', schedule.include_docs),
            ('media', schedule.include_media),
            ('database', schedule.include_database),
            ('static', schedule.include_static),
            ('templates', schedule.include_templates),
        ] if enabled
    ]

    context = {
        'schedule': schedule,
        'backups_page': backups_page,
        'selected_scopes': selected_scopes,
        'cron_expression': f'{schedule.cron_minute} * * * *',
        'format_file_size': _format_file_size,
    }
    return render(request, 'core/system_hub.html', context)


@login_required
@require_POST
def system_backup_run_now(request):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to create backups.')

    schedule = get_or_create_primary_schedule(updated_by=request.user)
    try:
        backup = create_system_backup(schedule, created_by=request.user, trigger='manual')
    except ValueError as exc:
        messages.error(request, str(exc))
    except Exception as exc:
        messages.error(request, f'Backup creation failed: {exc}')
    else:
        messages.success(request, f'Backup created: {backup.backup_name}')

    return redirect('system_hub')


@login_required
def system_backup_download(request, backup_id):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to download backups.')

    backup = get_object_or_404(SystemBackup, pk=backup_id)
    if not backup.archive:
        messages.error(request, 'Backup archive file is missing.')
        return redirect('system_hub')

    return FileResponse(
        backup.archive.open('rb'),
        as_attachment=True,
        filename=f'{backup.backup_name}.zip',
    )


@login_required
def system_backup_open(request, backup_id):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to open backups.')

    backup = get_object_or_404(SystemBackup, pk=backup_id)
    if not backup.archive:
        messages.error(request, 'Backup archive file is missing.')
        return redirect('system_hub')

    return redirect(backup.archive.url)


@login_required
@require_POST
def system_backup_restore(request, backup_id):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to restore backups.')

    backup = get_object_or_404(SystemBackup, pk=backup_id)
    try:
        restore_system_backup(backup)
        messages.success(request, f'Backup restored: {backup.backup_name}')
    except Exception as exc:
        messages.error(request, f'Unable to restore backup: {exc}')

    return redirect('system_hub')


@login_required
@require_POST
def system_backup_delete(request, backup_id):
    if not _can_manage_system_backups(request.user):
        return _permission_denied_response(request, 'You do not have permission to delete backups.')

    backup = get_object_or_404(SystemBackup, pk=backup_id)
    backup_name = backup.backup_name
    if backup.archive:
        backup.archive.delete(save=False)
    backup.delete()
    messages.success(request, f'Backup deleted: {backup_name}')
    return redirect('system_hub')
