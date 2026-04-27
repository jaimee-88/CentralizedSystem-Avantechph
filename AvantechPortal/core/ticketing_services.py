from django.contrib.auth import get_user_model
from django.db.models import Count, Max, Q
from django.utils import timezone

from .models import SupportTicket

User = get_user_model()

OPEN_TICKET_STATUS_VALUES = ('open', 'in_progress', 'waiting_user')
IMPORTANT_PRIORITY_VALUES = ('high', 'critical')

_IT_SUPPORT_ROLE_NAMES = (
    'IT Support',
    'IT-Support',
    'ITSupport',
)


def effective_priority_filter(priority_value):
    value = (priority_value or '').strip().lower()
    if not value:
        return Q()
    return (
        Q(support_priority=value)
        | Q(support_priority__isnull=True, requested_priority=value)
        | Q(support_priority='', requested_priority=value)
    )


def _it_support_role_filter():
    role_query = Q()
    for role_name in _IT_SUPPORT_ROLE_NAMES:
        role_query |= Q(groups__name__iexact=role_name)
    return role_query


def get_it_support_users_queryset():
    permission_query = Q(
        user_permissions__content_type__app_label='core',
        user_permissions__codename='can_manage_supportticket',
    ) | Q(
        groups__permissions__content_type__app_label='core',
        groups__permissions__codename='can_manage_supportticket',
    )
    support_candidates = (
        User.objects.filter(is_active=True)
        .filter(_it_support_role_filter() | permission_query)
        .distinct()
    )
    if support_candidates.exists():
        return support_candidates

    return User.objects.filter(is_active=True, is_superuser=True).distinct()


def can_manage_support_tickets(user):
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if user.is_superuser:
        return True
    if user.groups.filter(name__iexact='IT Support').exists() or user.groups.filter(name__iexact='IT-Support').exists() or user.groups.filter(name__iexact='ITSupport').exists():
        return True
    return user.has_perm('core.can_manage_supportticket')


def assign_ticket_fairly(ticket):
    if not ticket or not getattr(ticket, 'pk', None):
        return None

    support_users = list(get_it_support_users_queryset().order_by('id'))
    if not support_users:
        return None

    stats_rows = (
        SupportTicket.objects.filter(
            assigned_to_id__in=[user.id for user in support_users],
            status__in=OPEN_TICKET_STATUS_VALUES,
            is_archived=False,
        )
        .values('assigned_to_id')
        .annotate(open_count=Count('id'), last_assigned_at=Max('assigned_at'))
    )
    stats_map = {row['assigned_to_id']: row for row in stats_rows}
    fallback_time = timezone.now()

    def _sort_key(user_obj):
        stat = stats_map.get(user_obj.id) or {}
        open_count = int(stat.get('open_count') or 0)
        last_assigned_at = stat.get('last_assigned_at')
        return (
            open_count,
            1 if last_assigned_at else 0,
            last_assigned_at or fallback_time,
            user_obj.id,
        )

    chosen_user = min(support_users, key=_sort_key)

    update_fields = []
    if ticket.assigned_to_id != chosen_user.id:
        ticket.assigned_to = chosen_user
        update_fields.append('assigned_to')

    ticket.assigned_at = timezone.now()
    update_fields.append('assigned_at')
    update_fields.append('updated_at')
    ticket.save(update_fields=update_fields)
    return chosen_user
