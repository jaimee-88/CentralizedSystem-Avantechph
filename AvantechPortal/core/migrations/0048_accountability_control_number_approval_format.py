from django.db import migrations


def normalize_accountability_control_numbers(apps, schema_editor):
    AssetAccountability = apps.get_model('core', 'AssetAccountability')

    pending_or_declined = AssetAccountability.objects.exclude(request_status='approved')
    pending_or_declined.update(control_number=None, request_year=None, control_sequence=None)

    approved_records = AssetAccountability.objects.filter(
        request_status='approved',
        request_year__isnull=False,
        control_sequence__isnull=False,
    ).order_by('request_year', 'control_sequence', 'id')

    for record in approved_records:
        normalized_control_number = f'{record.request_year}-{record.control_sequence:04d}'
        if record.control_number == normalized_control_number:
            continue
        collision_exists = (
            AssetAccountability.objects
            .filter(control_number=normalized_control_number)
            .exclude(pk=record.pk)
            .exists()
        )
        if collision_exists:
            continue
        record.control_number = normalized_control_number
        record.save(update_fields=['control_number'])


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0047_assetaccountability_batch_id'),
    ]

    operations = [
        migrations.RunPython(normalize_accountability_control_numbers, migrations.RunPython.noop),
    ]
