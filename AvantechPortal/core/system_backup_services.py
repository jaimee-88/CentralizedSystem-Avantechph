from __future__ import annotations

import json
import logging
import tempfile
import zipfile
from pathlib import Path

from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from .models import SystemBackup, SystemBackupSchedule

SCOPE_DIRECTORY_MAP = {
    'logs': 'logs',
    'docs': 'docs',
    'media': 'media',
    'database': 'database',
    'static': 'static',
    'templates': 'templates',
}

logger = logging.getLogger(__name__)


def get_or_create_primary_schedule(updated_by=None):
    schedule = SystemBackupSchedule.objects.order_by('id').first()
    if schedule:
        return schedule

    return SystemBackupSchedule.objects.create(
        name='Primary Backup Schedule',
        updated_by=updated_by,
    )


def get_schedule_scopes(schedule):
    selected = []
    if schedule.include_logs:
        selected.append('logs')
    if schedule.include_docs:
        selected.append('docs')
    if schedule.include_media:
        selected.append('media')
    if schedule.include_database:
        selected.append('database')
    if schedule.include_static:
        selected.append('static')
    if schedule.include_templates:
        selected.append('templates')
    return selected


def _is_schedule_due(schedule, now=None):
    if not schedule.is_enabled:
        return False

    now = now or timezone.localtime(timezone.now())
    run_anchor = now.replace(minute=int(schedule.cron_minute or 0), second=0, microsecond=0)

    if now < run_anchor:
        return False

    if not schedule.last_run_at:
        return True

    last_run_local = timezone.localtime(schedule.last_run_at)
    if last_run_local.year == run_anchor.year and last_run_local.month == run_anchor.month and last_run_local.day == run_anchor.day and last_run_local.hour == run_anchor.hour:
        return False

    return last_run_local < run_anchor


def _safe_zip_write_directory(zip_handle, root_path, arc_prefix):
    if not root_path.exists() or not root_path.is_dir():
        return {'files_added': 0, 'skipped_count': 0, 'skipped_samples': []}

    count = 0
    skipped_samples = []
    skipped_count = 0
    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue

        # SQLite sidecar files are transient/lock-managed and commonly unreadable on Windows.
        if arc_prefix == 'database' and file_path.name.lower().endswith(('-shm', '-wal', '-journal')):
            skipped_count += 1
            continue

        relative_path = file_path.relative_to(root_path)
        arcname = str(Path(arc_prefix) / relative_path).replace('\\', '/')
        try:
            zip_handle.write(file_path, arcname=arcname)
            count += 1
        except OSError as exc:
            skipped_count += 1
            if len(skipped_samples) < 10:
                skipped_samples.append({'path': str(file_path), 'error': str(exc)})
            logger.warning('Skipping unreadable backup file: %s (%s)', file_path, exc)

    return {'files_added': count, 'skipped_count': skipped_count, 'skipped_samples': skipped_samples}


def _sanitize_zip_member(member_name):
    normalized = Path(member_name)
    if normalized.is_absolute():
        return None
    if '..' in normalized.parts:
        return None
    return normalized


def create_system_backup(schedule, created_by=None, trigger='manual'):
    selected_scopes = get_schedule_scopes(schedule)
    if not selected_scopes:
        raise ValueError('Select at least one backup scope.')

    base_dir = Path(settings.BASE_DIR)
    timestamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
    scope_suffix = '-'.join(selected_scopes)
    backup_name = f'system_backup_{timestamp}_{slugify(scope_suffix)[:50] or "scope"}'

    files_added = 0
    skipped_files = 0
    skipped_samples = []
    job_type = (schedule.job_type or 'backup_cleanup').strip()
    metadata = {
        'created_at': timezone.localtime(timezone.now()).isoformat(),
        'trigger': trigger,
        'job_type': job_type,
        'scopes': selected_scopes,
    }

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
        temp_zip_path = Path(tmp.name)

    try:
        with zipfile.ZipFile(temp_zip_path, mode='w', compression=zipfile.ZIP_DEFLATED) as archive:
            for scope in selected_scopes:
                relative_dir = SCOPE_DIRECTORY_MAP.get(scope)
                if not relative_dir:
                    continue
                source_dir = base_dir / relative_dir
                scope_result = _safe_zip_write_directory(archive, source_dir, scope)
                files_added += scope_result['files_added']
                skipped_files += scope_result['skipped_count']
                skipped_samples.extend(scope_result['skipped_samples'])

            if skipped_files:
                metadata['skipped_files'] = {
                    'count': skipped_files,
                    'samples': skipped_samples[:10],
                }

            archive.writestr('backup_metadata.json', json.dumps(metadata, indent=2))

        verification_ok = False
        if job_type == 'backup_verify':
            with zipfile.ZipFile(temp_zip_path, mode='r') as archive_to_verify:
                verification_ok = archive_to_verify.testzip() is None

        note_parts = [f'Files added: {files_added}']
        if skipped_files:
            note_parts.append(f'Skipped unreadable files: {skipped_files}')
        if job_type == 'backup_cleanup':
            note_parts.append('Mode: backup + cleanup')
        elif job_type == 'backup_verify':
            note_parts.append('Mode: backup + verify')
            note_parts.append('Verification: passed' if verification_ok else 'Verification: failed')
        else:
            note_parts.append('Mode: backup only')

        with temp_zip_path.open('rb') as zip_file:
            backup = SystemBackup(
                schedule=schedule,
                backup_name=backup_name,
                included_scopes=','.join(selected_scopes),
                trigger=trigger,
                created_by=created_by,
                notes=' | '.join(note_parts),
            )
            backup.archive.save(f'{backup_name}.zip', ContentFile(zip_file.read()), save=True)

        schedule.last_run_at = timezone.now()
        schedule.save(update_fields=['last_run_at'])

        enforce_schedule_retention(schedule)
        return backup
    finally:
        temp_zip_path.unlink(missing_ok=True)


def enforce_schedule_retention(schedule):
    max_backups = int(schedule.max_backups or 10)
    if max_backups < 1:
        max_backups = 1
    if max_backups > 10:
        max_backups = 10

    backup_ids_to_keep = list(
        SystemBackup.objects.filter(schedule=schedule).order_by('-created_at').values_list('id', flat=True)[:max_backups]
    )

    stale_records = SystemBackup.objects.filter(schedule=schedule).exclude(id__in=backup_ids_to_keep)
    for backup in stale_records:
        if backup.archive:
            backup.archive.delete(save=False)
        backup.delete()


def restore_system_backup(backup):
    if not backup.archive:
        raise ValueError('Backup archive is missing.')

    base_dir = Path(settings.BASE_DIR)
    scopes = set(backup.included_scopes_list)

    with zipfile.ZipFile(backup.archive.path, mode='r') as archive:
        for member in archive.namelist():
            sanitized = _sanitize_zip_member(member)
            if not sanitized:
                continue
            if sanitized.name == 'backup_metadata.json':
                continue

            top_level_scope = sanitized.parts[0] if sanitized.parts else ''
            if top_level_scope not in scopes:
                continue

            output_path = base_dir / sanitized
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, 'r') as source, output_path.open('wb') as destination:
                destination.write(source.read())

    backup.restore_count = int(backup.restore_count or 0) + 1
    backup.last_restored_at = timezone.now()
    backup.save(update_fields=['restore_count', 'last_restored_at'])


def run_due_system_backups(now=None):
    now = now or timezone.localtime(timezone.now())
    created = []
    schedules = SystemBackupSchedule.objects.filter(is_enabled=True).order_by('id')

    with transaction.atomic():
        for schedule in schedules.select_for_update():
            if not _is_schedule_due(schedule, now=now):
                continue
            backup = create_system_backup(schedule, created_by=None, trigger='scheduled')
            created.append(backup)

    return created
