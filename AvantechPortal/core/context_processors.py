from django.db.models import Q

from .models import Notification, SupportTicket
from .ticketing_services import (
    IMPORTANT_PRIORITY_VALUES,
    OPEN_TICKET_STATUS_VALUES,
    can_manage_support_tickets,
    effective_priority_filter,
)


def notification_summary(request):
    if not request.user.is_authenticated:
        return {
            'notifications': [],
            'unread_notification_count': 0,
        }

    notifications = list(
        Notification.objects.filter(user=request.user, is_read=False)
        .order_by('-created_at')[:5]
    )
    unread_notification_count = Notification.objects.filter(user=request.user, is_read=False).count()
    return {
        'notifications': notifications,
        'unread_notification_count': unread_notification_count,
    }


def finance_navigation_state(request):
    resolver_match = getattr(request, 'resolver_match', None)
    url_name = getattr(resolver_match, 'url_name', '') or ''
    is_finance_nav_active = (
        url_name.startswith('finance_')
        or url_name.startswith('fund_request')
        or url_name.startswith('liquidation')
    )
    is_asset_tracker_nav_active = (
        url_name.startswith('assets_')
        or url_name.startswith('accountability')
    )
    is_support_ticket_nav_active = url_name.startswith('support_ticket')

    important_ticket_count = 0
    if request.user.is_authenticated:
        important_query = SupportTicket.objects.filter(
            status__in=OPEN_TICKET_STATUS_VALUES,
            is_archived=False,
        ).filter(
            effective_priority_filter(IMPORTANT_PRIORITY_VALUES[0]) | effective_priority_filter(IMPORTANT_PRIORITY_VALUES[1])
        )
        if request.user.is_superuser:
            important_ticket_count = important_query.count()
        elif can_manage_support_tickets(request.user):
            important_ticket_count = important_query.filter(
                Q(assigned_to=request.user) | Q(assigned_to__isnull=True) | Q(created_by=request.user)
            ).count()
        else:
            important_ticket_count = important_query.filter(created_by=request.user).count()

    return {
        'is_finance_nav_active': is_finance_nav_active,
        'is_asset_tracker_nav_active': is_asset_tracker_nav_active,
        'is_support_ticket_nav_active': is_support_ticket_nav_active,
        'important_ticket_count': important_ticket_count,
    }
