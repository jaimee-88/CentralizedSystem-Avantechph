from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .forms import (
    SupportTicketCreateForm,
    SupportTicketMessageForm,
    SupportTicketRequesterPriorityForm,
    SupportTicketSupportUpdateForm,
)
from .models import SupportTicket
from .notifications import create_notification
from .ticketing_services import (
    IMPORTANT_PRIORITY_VALUES,
    OPEN_TICKET_STATUS_VALUES,
    assign_ticket_fairly,
    can_manage_support_tickets,
    effective_priority_filter,
)


def _permission_denied_response(request, message='You do not have permission to perform this action.'):
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'ok': False, 'message': message}, status=403)

    messages.error(request, message, extra_tags='permission-modal')
    referer = (request.META.get('HTTP_REFERER') or '').strip()
    if referer and url_has_allowed_host_and_scheme(referer, {request.get_host()}):
        return redirect(referer)
    return redirect('dashboard')


def _can_access_ticket(user, ticket, can_manage=None):
    if not user or not user.is_authenticated:
        return False
    if can_manage is None:
        can_manage = can_manage_support_tickets(user)
    if user.is_superuser:
        return True
    if ticket.created_by_id == user.id or ticket.assigned_to_id == user.id:
        return True
    return bool(can_manage and ticket.assigned_to_id is None)


def _can_chat_on_ticket(user, ticket):
    if not user or not user.is_authenticated:
        return False
    return user.id in {ticket.created_by_id, ticket.assigned_to_id}


def _parse_selected_ticket_ids(post_data):
    parsed_ids = []
    for raw_value in post_data.getlist('ticket_ids'):
        try:
            parsed_ids.append(int(str(raw_value).strip()))
        except (TypeError, ValueError):
            continue
    return sorted(set(parsed_ids))


@login_required
def support_tickets_list(request):
    can_manage = can_manage_support_tickets(request.user)
    is_admin = request.user.is_superuser
    query = (request.GET.get('q') or '').strip()
    status_filter = (request.GET.get('status') or 'all').strip().lower()
    priority_filter = (request.GET.get('priority') or 'all').strip().lower()

    visible_tickets = SupportTicket.objects.select_related('created_by', 'assigned_to').filter(is_archived=False)
    if can_manage and not request.user.is_superuser:
        visible_tickets = visible_tickets.filter(
            Q(assigned_to=request.user) | Q(created_by=request.user) | Q(assigned_to__isnull=True)
        )
    elif not can_manage:
        visible_tickets = visible_tickets.filter(created_by=request.user)

    ticket_queryset = visible_tickets
    if query:
        ticket_queryset = ticket_queryset.filter(
            Q(ticket_number__icontains=query)
            | Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(created_by__username__icontains=query)
            | Q(created_by__first_name__icontains=query)
            | Q(created_by__last_name__icontains=query)
            | Q(assigned_to__username__icontains=query)
            | Q(assigned_to__first_name__icontains=query)
            | Q(assigned_to__last_name__icontains=query)
        )

    valid_statuses = {choice[0] for choice in SupportTicket.STATUS_CHOICES}
    if status_filter in valid_statuses:
        ticket_queryset = ticket_queryset.filter(status=status_filter)
    else:
        status_filter = 'all'

    valid_priorities = {choice[0] for choice in SupportTicket.PRIORITY_CHOICES}
    if priority_filter in valid_priorities:
        ticket_queryset = ticket_queryset.filter(effective_priority_filter(priority_filter))
    else:
        priority_filter = 'all'

    ticket_page = Paginator(ticket_queryset.order_by('-created_at'), 10).get_page(request.GET.get('page'))
    important_open_count = visible_tickets.filter(status__in=OPEN_TICKET_STATUS_VALUES).filter(
        effective_priority_filter('high') | effective_priority_filter('critical')
    ).count()
    open_count = visible_tickets.filter(status__in=OPEN_TICKET_STATUS_VALUES).count()
    resolved_count = visible_tickets.filter(status='resolved').count()
    closed_count = visible_tickets.filter(status='closed').count()
    archived_ticket_count = 0
    archived_tickets_preview = []
    if is_admin:
        archived_tickets_qs = SupportTicket.objects.select_related('created_by', 'assigned_to', 'archived_by').filter(is_archived=True)
        archived_ticket_count = archived_tickets_qs.count()
        archived_tickets_preview = archived_tickets_qs.order_by('-archived_at', '-updated_at')[:25]

    context = {
        'can_manage_support_tickets': can_manage,
        'is_admin': is_admin,
        'create_form': SupportTicketCreateForm(),
        'ticket_page': ticket_page,
        'ticket_query': query,
        'status_filter': status_filter,
        'priority_filter': priority_filter,
        'open_count': open_count,
        'resolved_count': resolved_count,
        'closed_count': closed_count,
        'important_open_count': important_open_count,
        'archived_ticket_count': archived_ticket_count,
        'archived_tickets_preview': archived_tickets_preview,
        'status_choices': [('all', 'All Statuses')] + list(SupportTicket.STATUS_CHOICES),
        'priority_choices': [('all', 'All Priorities')] + list(SupportTicket.PRIORITY_CHOICES),
    }
    return render(request, 'core/support_tickets_list.html', context)


@login_required
@require_POST
def support_ticket_create(request):
    form = SupportTicketCreateForm(request.POST)
    if not form.is_valid():
        for _, errors in form.errors.items():
            if errors:
                messages.error(request, errors[0])
                break
        return redirect('support_tickets_list')

    with transaction.atomic():
        ticket = form.save(commit=False)
        ticket.created_by = request.user
        ticket.status = 'open'
        ticket.last_message_at = timezone.now()
        ticket.save()
        assigned_user = assign_ticket_fairly(ticket)

    detail_url = reverse('support_ticket_detail', args=[ticket.id])
    create_notification(
        request.user,
        title='Ticket submitted',
        message=f'{ticket.ticket_number} was submitted successfully.',
        link_url=detail_url,
    )

    if assigned_user and assigned_user.id != request.user.id:
        priority_label = ticket.effective_priority.title()
        assignment_title = 'New support ticket assigned'
        if ticket.effective_priority in IMPORTANT_PRIORITY_VALUES:
            assignment_title = f'Important ticket assigned ({priority_label})'
        create_notification(
            assigned_user,
            title=assignment_title,
            message=f'{ticket.ticket_number}: {ticket.title}',
            link_url=detail_url,
        )

    if not assigned_user:
        messages.warning(request, 'Ticket created, but no active IT Support user was found for assignment yet.')
    else:
        assignee_name = assigned_user.get_full_name() or assigned_user.username
        messages.success(request, f'Ticket created and assigned to {assignee_name}.')

    return redirect('support_ticket_detail', ticket_id=ticket.id)


@login_required
def support_ticket_detail(request, ticket_id):
    ticket = get_object_or_404(SupportTicket.objects.select_related('created_by', 'assigned_to'), pk=ticket_id)
    can_manage = can_manage_support_tickets(request.user)
    if not _can_access_ticket(request.user, ticket, can_manage=can_manage):
        return _permission_denied_response(request, 'You do not have permission to view this ticket.')

    can_chat = (not ticket.is_archived) and _can_chat_on_ticket(request.user, ticket)
    can_update_support = (not ticket.is_archived) and (can_manage or request.user.id == ticket.assigned_to_id)
    can_update_requested_priority = (not ticket.is_archived) and (request.user.id == ticket.created_by_id or request.user.is_superuser)

    context = {
        'ticket': ticket,
        'messages_list': ticket.messages.select_related('sender').all(),
        'can_manage_support_tickets': can_manage,
        'can_chat': can_chat,
        'can_update_support': can_update_support,
        'can_update_requested_priority': can_update_requested_priority,
        'message_form': SupportTicketMessageForm(),
        'requester_priority_form': SupportTicketRequesterPriorityForm(instance=ticket),
        'support_update_form': SupportTicketSupportUpdateForm(instance=ticket),
    }
    return render(request, 'core/support_ticket_detail.html', context)


@login_required
@require_POST
def support_ticket_add_message(request, ticket_id):
    ticket = get_object_or_404(SupportTicket.objects.select_related('created_by', 'assigned_to'), pk=ticket_id)
    if ticket.is_archived:
        return _permission_denied_response(request, 'Archived tickets are read-only.')
    can_manage = can_manage_support_tickets(request.user)
    if not _can_access_ticket(request.user, ticket, can_manage=can_manage):
        return _permission_denied_response(request, 'You do not have permission to view this ticket.')
    if not _can_chat_on_ticket(request.user, ticket):
        return _permission_denied_response(request, 'This conversation is private to the requester and assigned IT support.')

    form = SupportTicketMessageForm(request.POST)
    if not form.is_valid():
        for _, errors in form.errors.items():
            if errors:
                messages.error(request, errors[0])
                break
        return redirect('support_ticket_detail', ticket_id=ticket.id)

    message = form.save(commit=False)
    message.ticket = ticket
    message.sender = request.user
    message.save()

    fields_to_update = ['last_message_at', 'updated_at']
    ticket.last_message_at = timezone.now()
    if request.user.id == ticket.created_by_id and ticket.status == 'waiting_user':
        ticket.status = 'open'
        ticket.closed_at = None
        fields_to_update.extend(['status', 'closed_at'])
    elif request.user.id == ticket.assigned_to_id and ticket.status == 'open':
        ticket.status = 'in_progress'
        fields_to_update.append('status')
    ticket.save(update_fields=fields_to_update)

    sender_name = request.user.get_full_name() or request.user.username
    detail_url = reverse('support_ticket_detail', args=[ticket.id])
    recipient_ids = {ticket.created_by_id, ticket.assigned_to_id}
    recipient_ids.discard(request.user.id)
    recipient_ids.discard(None)

    for user_id in recipient_ids:
        recipient = ticket.created_by if ticket.created_by_id == user_id else ticket.assigned_to
        if recipient:
            create_notification(
                recipient,
                title=f'Ticket reply: {ticket.ticket_number}',
                message=f'{sender_name}: {message.message[:90]}',
                link_url=detail_url,
            )

    messages.success(request, 'Reply sent.')
    return redirect('support_ticket_detail', ticket_id=ticket.id)


@login_required
@require_POST
def support_ticket_update_requested_priority(request, ticket_id):
    ticket = get_object_or_404(SupportTicket.objects.select_related('created_by', 'assigned_to'), pk=ticket_id)
    if ticket.is_archived:
        return _permission_denied_response(request, 'Archived tickets are read-only.')
    if not (request.user.id == ticket.created_by_id or request.user.is_superuser):
        return _permission_denied_response(request, 'Only the ticket requester can update requested priority.')

    old_priority = ticket.requested_priority
    old_effective_priority = ticket.effective_priority
    form = SupportTicketRequesterPriorityForm(request.POST, instance=ticket)
    if not form.is_valid():
        for _, errors in form.errors.items():
            if errors:
                messages.error(request, errors[0])
                break
        return redirect('support_ticket_detail', ticket_id=ticket.id)

    updated_ticket = form.save(commit=False)
    updated_ticket.closed_at = ticket.closed_at
    updated_ticket.save(update_fields=['requested_priority', 'updated_at'])
    ticket.refresh_from_db(fields=['requested_priority', 'support_priority'])

    if old_priority != updated_ticket.requested_priority:
        detail_url = reverse('support_ticket_detail', args=[ticket.id])
        if ticket.assigned_to:
            create_notification(
                ticket.assigned_to,
                title=f'Requested priority updated ({ticket.effective_priority.title()})',
                message=f'{ticket.ticket_number}: requester changed priority.',
                link_url=detail_url,
            )
        if old_effective_priority != ticket.effective_priority and ticket.effective_priority in IMPORTANT_PRIORITY_VALUES:
            messages.warning(request, 'Priority updated to an important level (High/Critical).')
        else:
            messages.success(request, 'Requested priority updated.')
    else:
        messages.info(request, 'No priority change detected.')

    return redirect('support_ticket_detail', ticket_id=ticket.id)


@login_required
@require_POST
def support_ticket_update_support(request, ticket_id):
    ticket = get_object_or_404(SupportTicket.objects.select_related('created_by', 'assigned_to'), pk=ticket_id)
    if ticket.is_archived:
        return _permission_denied_response(request, 'Archived tickets are read-only.')
    can_manage = can_manage_support_tickets(request.user)
    if not (can_manage or request.user.id == ticket.assigned_to_id):
        return _permission_denied_response(request, 'You do not have permission to update this ticket.')

    old_status = ticket.status
    old_support_priority = ticket.support_priority or ''
    old_effective_priority = ticket.effective_priority
    form = SupportTicketSupportUpdateForm(request.POST, instance=ticket)
    if not form.is_valid():
        for _, errors in form.errors.items():
            if errors:
                messages.error(request, errors[0])
                break
        return redirect('support_ticket_detail', ticket_id=ticket.id)

    updated_ticket = form.save(commit=False)
    ticket.status = updated_ticket.status
    ticket.support_priority = updated_ticket.support_priority or None

    if ticket.status in {'resolved', 'closed'}:
        ticket.closed_at = timezone.now()
    else:
        ticket.closed_at = None

    ticket.save(update_fields=['status', 'support_priority', 'closed_at', 'updated_at'])
    if not ticket.assigned_to_id:
        assign_ticket_fairly(ticket)
        ticket.refresh_from_db(fields=['assigned_to', 'assigned_at'])

    detail_url = reverse('support_ticket_detail', args=[ticket.id])
    changed = (
        old_status != ticket.status
        or old_support_priority != (ticket.support_priority or '')
    )
    if changed:
        status_label = ticket.get_status_display()
        priority_label = ticket.effective_priority.title()
        create_notification(
            ticket.created_by,
            title=f'Ticket updated: {ticket.ticket_number}',
            message=f'Status: {status_label} | Priority: {priority_label}',
            link_url=detail_url,
        )
        if old_effective_priority != ticket.effective_priority and ticket.effective_priority in IMPORTANT_PRIORITY_VALUES:
            messages.warning(request, 'Ticket updated with important priority (High/Critical).')
        else:
            messages.success(request, 'Ticket updated successfully.')
    else:
        messages.info(request, 'No support update changes detected.')

    return redirect('support_ticket_detail', ticket_id=ticket.id)


@login_required
@require_POST
def support_tickets_bulk_archive(request):
    if not request.user.is_superuser:
        return _permission_denied_response(request, 'Only admin can archive tickets.')

    selected_ids = _parse_selected_ticket_ids(request.POST)
    if not selected_ids:
        messages.warning(request, 'Select at least one ticket to archive.')
        return redirect('support_tickets_list')

    now = timezone.now()
    updated_count = (
        SupportTicket.objects.filter(id__in=selected_ids, is_archived=False)
        .update(
            is_archived=True,
            archived_at=now,
            archived_by=request.user,
            status='closed',
            closed_at=now,
            updated_at=now,
        )
    )
    if updated_count:
        messages.success(request, f'{updated_count} ticket(s) archived successfully.')
    else:
        messages.info(request, 'No eligible tickets were archived.')
    return redirect('support_tickets_list')


@login_required
@require_POST
def support_tickets_bulk_delete(request):
    if not request.user.is_superuser:
        return _permission_denied_response(request, 'Only admin can delete tickets.')

    selected_ids = _parse_selected_ticket_ids(request.POST)
    if not selected_ids:
        messages.warning(request, 'Select at least one ticket to delete.')
        return redirect('support_tickets_list')

    delete_qs = SupportTicket.objects.filter(id__in=selected_ids)
    deleted_count = delete_qs.count()
    delete_qs.delete()
    if deleted_count:
        messages.success(request, f'{deleted_count} ticket(s) deleted successfully.')
    else:
        messages.info(request, 'No eligible tickets were deleted.')
    return redirect('support_tickets_list')
