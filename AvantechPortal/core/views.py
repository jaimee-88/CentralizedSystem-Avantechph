from datetime import timedelta
from decimal import Decimal, InvalidOperation
import base64
import csv
from functools import lru_cache
from io import BytesIO
from json import dumps
import os
import secrets
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
from urllib.parse import quote
import zipfile
from xml.sax.saxutils import escape
import re
import textwrap
import xml.etree.ElementTree as ET

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.utils import OperationalError
from django.db.models import Count, Max, Sum
from django.db.models import Q
from django.db.models.functions import TruncMonth
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.http import urlencode
from django.views import View
from django.views.generic import FormView, TemplateView
from django.views.decorators.http import require_POST
from axes.models import AccessAttempt, AccessFailureLog
from axes.utils import reset as axes_reset
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from PIL import Image, ImageDraw, ImageFont, ImageOps
try:
	from pypdf import PdfReader, PdfWriter
except Exception:
	PdfReader = None
	PdfWriter = None

try:
	import qrcode
	from qrcode.image.svg import SvgImage
except Exception:
	qrcode = None
	SvgImage = None

from .auth_utils import invalidate_user_sessions
from .forms import (
	AssetAccountabilityForm,
	AssetAccountabilityTemplateForm,
	AssetDepartmentForm,
	AssetItemForm,
	AssetItemTypeForm,
	ClientForm,
	ClientQuotationForm,
	CompanyInternetAccountForm,
	CompanyInternetAccountUnlockForm,
	DeveloperFeedbackForm,
	EmailVerificationRequestForm,
	EmailVerificationOTPForm,
	FundRequestForm,
	FundRequestTemplateForm,
	LiquidationForm,
	LiquidationTemplateForm,
	PatchNoteCommentForm,
	PatchNoteForm,
	LockoutResetForm,
	OTPVerificationForm,
	RoleForm,
	SecureAuthenticationForm,
	SecurePasswordChangeForm,
	StaffUserCreationForm,
	StaffUserUpdateForm,
	UserStatusForm,
)
from .models import (
	AssetAccountability,
	AssetAccountabilityTemplate,
	AssetDepartment,
	AssetItem,
	AssetItemImage,
	AssetItemType,
	AssetReturnProof,
	AssetTagBatch,
	AssetTagEntry,
	Client,
	ClientDeletionRequest,
	ClientQuotation,
	ClientQuotationDocument,
	CompanyInternetAccount,
	DevelopmentFeedback,
	DevelopmentFeedbackComment,
	EmailVerificationToken,
	FundRequest,
	FundRequestAttachment,
	FundRequestAutoApproveRule,
	FundRequestLineItem,
	FundRequestTemplate,
	Liquidation,
	LiquidationAttachment,
	LiquidationLineItem,
	LiquidationSettings,
	LiquidationTemplate,
	LoginEvent,
	Notification,
	PatchNote,
	PatchNoteAttachment,
	PatchNoteComment,
	PatchNoteReaction,
	UserProfile,
)
from .notifications import create_notification
from .permission_catalog import build_permission_preview_groups, format_permission_summary


EMAIL_VERIFICATION_CODE_TTL = 10 * 60
EMAIL_VERIFICATION_RESEND_COOLDOWN = 60
INTERNET_ACCOUNT_UNLOCK_TTL_SECONDS = 5 * 60
INTERNET_ACCOUNT_UNLOCK_SESSION_KEY = 'company_internet_account_unlocks'


def _set_user_status(user, status):
	profile, _ = UserProfile.objects.get_or_create(user=user)
	if profile.status != status:
		profile.status = status
		profile.save(update_fields=['status'])


def _sync_presence_session(request, status, event_ms=None):
	if event_ms is None:
		event_ms = int(timezone.now().timestamp() * 1000)

	request.session['presence_status'] = status
	request.session['presence_last_event_ms'] = int(event_ms)
	if not request.session.get('presence_session_id'):
		request.session['presence_session_id'] = secrets.token_hex(16)


def _format_last_activity_label(last_event_ms):
	if not last_event_ms:
		return 'Unknown'

	try:
		event_dt = timezone.datetime.fromtimestamp(int(last_event_ms) / 1000, tz=timezone.UTC)
	except (TypeError, ValueError, OSError):
		return 'Unknown'

	now = timezone.now()
	delta = now - event_dt
	total_seconds = max(0, int(delta.total_seconds()))

	if total_seconds < 60:
		return 'Just now'
	if total_seconds < 3600:
		minutes = total_seconds // 60
		return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
	if total_seconds < 86400:
		hours = total_seconds // 3600
		return f'{hours} hour{"s" if hours != 1 else ""} ago'

	days = total_seconds // 86400
	return f'{days} day{"s" if days != 1 else ""} ago'


def _email_verification_code_key(user_id):
	return f'email-verification-code:{user_id}'


def _email_verification_sent_at_key(user_id):
	return f'email-verification-sent-at:{user_id}'


def _get_email_verification_resend_remaining(user):
	sent_at = cache.get(_email_verification_sent_at_key(user.pk))
	if not sent_at:
		return 0
	elapsed = max(0, int(timezone.now().timestamp() - float(sent_at)))
	return max(0, EMAIL_VERIFICATION_RESEND_COOLDOWN - elapsed)


def _send_email_verification_code(request, user):
	code = f'{secrets.randbelow(1000000):06d}'
	cache.set(_email_verification_code_key(user.pk), code, timeout=EMAIL_VERIFICATION_CODE_TTL)
	cache.set(_email_verification_sent_at_key(user.pk), timezone.now().timestamp(), timeout=EMAIL_VERIFICATION_CODE_TTL)
	verify_url = request.build_absolute_uri(reverse('email_verification_otp'))
	send_mail(
		subject='Verify your Avantech Portal email',
		message=(
			f'Your Avantech Portal verification code is: {code}\n\n'
			f'Enter this code here: {verify_url}\n\n'
			f'This code expires in 10 minutes.'
		),
		from_email=settings.DEFAULT_FROM_EMAIL,
		recipient_list=[user.email],
		fail_silently=False,
	)


def landing(request):
	if request.user.is_authenticated:
		return redirect('dashboard')
	return render(request, 'core/landing.html')


class SecureLoginView(FormView):
	template_name = 'registration/login.html'
	form_class = SecureAuthenticationForm

	def dispatch(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			return redirect('dashboard')
		return super().dispatch(request, *args, **kwargs)

	def get_success_url(self):
		redirect_to = self.request.POST.get('next') or self.request.GET.get('next')
		if redirect_to and url_has_allowed_host_and_scheme(redirect_to, {self.request.get_host()}):
			return redirect_to
		return reverse('dashboard')

	def get_form_kwargs(self):
		kwargs = super().get_form_kwargs()
		kwargs['request'] = self.request
		return kwargs

	def form_valid(self, form):
		user = form.get_user()
		self.request.session['pre_2fa_user_id'] = user.pk
		self.request.session['post_login_redirect'] = self.get_success_url()

		has_2fa_device = any(devices_for_user(user, confirmed=True))
		if has_2fa_device:
			return redirect('otp_verify')

		login(self.request, user)
		_set_user_status(user, 'active')
		_sync_presence_session(self.request, 'active')
		return redirect(self.request.session.pop('post_login_redirect', reverse('dashboard')))


class OTPVerifyView(FormView):
	template_name = 'registration/otp_verify.html'
	form_class = OTPVerificationForm

	def dispatch(self, request, *args, **kwargs):
		if not request.session.get('pre_2fa_user_id'):
			messages.error(request, 'Your login session expired. Please sign in again.')
			return redirect('login')
		return super().dispatch(request, *args, **kwargs)

	def form_valid(self, form):
		user_id = self.request.session.get('pre_2fa_user_id')
		token = form.cleaned_data['token']
		user = get_object_or_404(User, pk=user_id)

		for device in devices_for_user(user, confirmed=True):
			if device.verify_token(token):
				login(self.request, user)
				_set_user_status(user, 'active')
				_sync_presence_session(self.request, 'active')
				self.request.session.pop('pre_2fa_user_id', None)
				return redirect(self.request.session.pop('post_login_redirect', reverse('dashboard')))

		form.add_error('token', 'Invalid verification code.')
		return self.form_invalid(form)


class SecureLogoutView(View):
	def post(self, request, *args, **kwargs):
		if request.user.is_authenticated:
			_set_user_status(request.user, 'offline')
			invalidate_user_sessions(request.user)
		logout(request)
		request.session.flush()
		return redirect(settings.LOGOUT_REDIRECT_URL)


@login_required
def dashboard(request):
	if not request.session.get('presence_session_id'):
		_sync_presence_session(request, request.user.profile.status)

	allowed_ranges = [30, 90, 180]
	raw_range = (request.GET.get('range') or '180').strip()
	try:
		selected_range_days = int(raw_range)
	except (TypeError, ValueError):
		selected_range_days = 180
	if selected_range_days not in allowed_ranges:
		selected_range_days = 180

	can_view_clients = request.user.is_superuser or request.user.has_perm('core.view_client')
	context = {
		'can_view_clients': can_view_clients,
		'selected_range_days': selected_range_days,
		'sales_range_options': allowed_ranges,
		'intake_leads': 0,
		'qualified_leads': 0,
		'converted_leads': 0,
		'not_qualified_leads': 0,
		'lost_leads': 0,
		'top_agent_name': '-',
		'top_agent_score': 0,
		'top_agent_conversion_rate': 0,
		'top_agent_recovery_target': 0,
		'agent_performance_rows': [],
		'agent_labels_json': '[]',
		'agent_intake_json': '[]',
		'agent_qualified_json': '[]',
		'agent_not_qualified_json': '[]',
		'agent_lost_json': '[]',
		'agent_converted_json': '[]',
		'agent_weighted_score_json': '[]',
		'total_quotations': 0,
		'accepted_quotations': 0,
		'total_quoted_amount': 0,
		'accepted_quoted_amount': 0,
		'quotation_acceptance_rate': 0,
		'monthly_labels_json': '[]',
		'monthly_sent_json': '[]',
		'monthly_accepted_json': '[]',
		'monthly_accepted_amount_json': '[]',
	}

	if can_view_clients:
		agent_rows = User.objects.filter(handled_clients__isnull=False).annotate(
			intake_count=Count('handled_clients', filter=Q(handled_clients__lead_status='intake')),
			qualified_count=Count('handled_clients', filter=Q(handled_clients__lead_status='qualified')),
			not_qualified_count=Count('handled_clients', filter=Q(handled_clients__lead_status='not_qualified')),
			lost_count=Count('handled_clients', filter=Q(handled_clients__lead_status='lost')),
			converted_count=Count('handled_clients', filter=Q(handled_clients__lead_status='converted')),
		).order_by('-converted_count', '-qualified_count', 'username')

		agent_labels = []
		agent_intake = []
		agent_qualified = []
		agent_not_qualified = []
		agent_lost = []
		agent_converted = []
		agent_weighted_scores = []
		agent_performance_rows = []
		top_agent_name = '-'
		top_agent_score = None
		top_agent_conversion_rate = 0
		top_agent_recovery_target = 0

		for agent in agent_rows:
			display_name = (agent.get_full_name() or agent.username or '').strip() or f'User {agent.pk}'
			intake_count = int(agent.intake_count or 0)
			qualified_count = int(agent.qualified_count or 0)
			not_qualified_count = int(agent.not_qualified_count or 0)
			lost_count = int(agent.lost_count or 0)
			converted_count = int(agent.converted_count or 0)
			total_leads_count = intake_count + qualified_count + not_qualified_count + lost_count + converted_count

			# Performance weights: converted has higher impact (+2), and lost is double recovery (-4).
			weighted_score = (converted_count * 2) + qualified_count - not_qualified_count - (lost_count * 4)
			conversion_rate = round((converted_count / total_leads_count) * 100, 2) if total_leads_count else 0
			recovery_target = max((lost_count * 2) - converted_count, 0)

			agent_labels.append(display_name)
			agent_intake.append(intake_count)
			agent_qualified.append(qualified_count)
			agent_not_qualified.append(not_qualified_count)
			agent_lost.append(lost_count)
			agent_converted.append(converted_count)
			agent_weighted_scores.append(weighted_score)

			agent_performance_rows.append(
				{
					'name': display_name,
					'total_leads': total_leads_count,
					'converted': converted_count,
					'lost': lost_count,
					'conversion_rate': conversion_rate,
					'recovery_target': recovery_target,
					'weighted_score': weighted_score,
				}
			)

			if top_agent_score is None or weighted_score > top_agent_score:
				top_agent_name = display_name
				top_agent_score = weighted_score
				top_agent_conversion_rate = conversion_rate
				top_agent_recovery_target = recovery_target

		context.update(
			{
				'intake_leads': Client.objects.filter(lead_status='intake').count(),
				'qualified_leads': Client.objects.filter(lead_status='qualified').count(),
				'converted_leads': Client.objects.filter(lead_status='converted').count(),
				'not_qualified_leads': Client.objects.filter(lead_status='not_qualified').count(),
				'lost_leads': Client.objects.filter(lead_status='lost').count(),
				'top_agent_name': top_agent_name,
				'top_agent_score': int(top_agent_score or 0),
				'top_agent_conversion_rate': top_agent_conversion_rate,
				'top_agent_recovery_target': top_agent_recovery_target,
				'agent_performance_rows': agent_performance_rows,
				'agent_labels_json': dumps(agent_labels),
				'agent_intake_json': dumps(agent_intake),
				'agent_qualified_json': dumps(agent_qualified),
				'agent_not_qualified_json': dumps(agent_not_qualified),
				'agent_lost_json': dumps(agent_lost),
				'agent_converted_json': dumps(agent_converted),
				'agent_weighted_score_json': dumps(agent_weighted_scores),
			}
		)

		range_start = timezone.now() - timedelta(days=selected_range_days)
		quotations_in_range = ClientQuotation.objects.filter(sent_at__gte=range_start)

		quotation_aggregates = quotations_in_range.aggregate(
			total_quoted_amount=Sum('quoted_amount'),
			accepted_quoted_amount=Sum('quoted_amount', filter=Q(negotiation_status='accepted')),
		)
		total_quotations = quotations_in_range.count()
		accepted_quotations = quotations_in_range.filter(negotiation_status='accepted').count()
		quotation_acceptance_rate = round((accepted_quotations / total_quotations) * 100, 2) if total_quotations else 0

		monthly_rows = (
			quotations_in_range
			.annotate(month=TruncMonth('sent_at'))
			.values('month')
			.annotate(
				sent_count=Count('id'),
				accepted_count=Count('id', filter=Q(negotiation_status='accepted')),
				accepted_amount=Sum('quoted_amount', filter=Q(negotiation_status='accepted')),
			)
			.order_by('month')
		)

		monthly_labels = []
		monthly_sent = []
		monthly_accepted = []
		monthly_accepted_amount = []
		for row in monthly_rows:
			month_value = row.get('month')
			monthly_labels.append(month_value.strftime('%b %Y') if month_value else '-')
			monthly_sent.append(int(row.get('sent_count') or 0))
			monthly_accepted.append(int(row.get('accepted_count') or 0))
			monthly_accepted_amount.append(float(row.get('accepted_amount') or 0))

		context.update(
			{
				'total_quotations': total_quotations,
				'accepted_quotations': accepted_quotations,
				'total_quoted_amount': quotation_aggregates.get('total_quoted_amount') or 0,
				'accepted_quoted_amount': quotation_aggregates.get('accepted_quoted_amount') or 0,
				'quotation_acceptance_rate': quotation_acceptance_rate,
				'monthly_labels_json': dumps(monthly_labels),
				'monthly_sent_json': dumps(monthly_sent),
				'monthly_accepted_json': dumps(monthly_accepted),
				'monthly_accepted_amount_json': dumps(monthly_accepted_amount),
			}
		)

	return render(request, 'core/dashboard.html', context)


@login_required
def development_hub(request):
	can_manage_feedback = request.user.is_superuser or request.user.has_perm('core.change_developmentfeedback')
	feedback_query = (request.GET.get('feedback_q') or '').strip()

	if request.method == 'POST':
		form = DeveloperFeedbackForm(request.POST)
		if form.is_valid():
			feedback = form.save(commit=False)
			feedback.created_by = request.user
			feedback.save()
			messages.success(request, 'Thank you. Your feedback was submitted to the development queue.')
			return redirect('development_hub')
	else:
		form = DeveloperFeedbackForm()

	feedback_queryset = DevelopmentFeedback.objects.select_related('created_by').prefetch_related('comments', 'comments__created_by')
	if not can_manage_feedback:
		feedback_queryset = feedback_queryset.filter(created_by=request.user)

	if feedback_query:
		feedback_filters = Q(title__icontains=feedback_query) | Q(message__icontains=feedback_query) | Q(category__icontains=feedback_query)
		if can_manage_feedback:
			feedback_filters = feedback_filters | Q(created_by__username__icontains=feedback_query) | Q(created_by__first_name__icontains=feedback_query) | Q(created_by__last_name__icontains=feedback_query)
		feedback_queryset = feedback_queryset.filter(feedback_filters)

	feedback_page = Paginator(feedback_queryset.order_by('-created_at'), 10).get_page(request.GET.get('feedback_page'))
	feedback_page_numbers = list(feedback_page.paginator.page_range)

	context = {
		'form': form,
		'feedback_page': feedback_page,
		'feedback_page_numbers': feedback_page_numbers,
		'feedback_q': feedback_query,
		'can_manage_feedback': can_manage_feedback,
	}
	return render(request, 'core/development_hub.html', context)


@login_required
@require_POST
def development_feedback_add_comment(request, feedback_id):
	can_manage_feedback = request.user.is_superuser or request.user.has_perm('core.change_developmentfeedback')
	if not can_manage_feedback:
		return _permission_denied_response(request, 'You do not have permission to comment on feedback.')

	feedback = get_object_or_404(DevelopmentFeedback, pk=feedback_id)
	comment = (request.POST.get('comment') or '').strip()
	if not comment:
		messages.warning(request, 'Comment cannot be empty.')
		return redirect('development_hub')

	DevelopmentFeedbackComment.objects.create(
		feedback=feedback,
		comment=comment,
		created_by=request.user,
	)
	if feedback.status == 'new':
		feedback.status = 'in_review'
		feedback.save(update_fields=['status', 'updated_at'])

	messages.success(request, 'Comment posted on feedback.')
	return redirect('development_hub')


@login_required
@require_POST
def development_feedback_update_status(request, feedback_id):
	can_manage_feedback = request.user.is_superuser or request.user.has_perm('core.change_developmentfeedback')
	if not can_manage_feedback:
		return _permission_denied_response(request, 'You do not have permission to update feedback status.')

	feedback = get_object_or_404(DevelopmentFeedback, pk=feedback_id)
	redirect_url = request.POST.get('next') or reverse('development_hub')
	status = (request.POST.get('status') or '').strip()
	allowed_statuses = {choice[0] for choice in DevelopmentFeedback.STATUS_CHOICES}
	if status not in allowed_statuses:
		messages.error(request, 'Invalid feedback status.')
		return redirect(redirect_url)

	if status == feedback.status:
		messages.info(request, 'No status change detected.')
		return redirect(redirect_url)

	feedback.status = status
	feedback.save(update_fields=['status', 'updated_at'])
	messages.success(request, f'Feedback status updated to "{feedback.get_status_display()}".')
	return redirect(redirect_url)


@login_required
@require_POST
def development_feedback_delete(request, feedback_id):
	can_manage_feedback = request.user.is_superuser or request.user.has_perm('core.delete_developmentfeedback')
	if not can_manage_feedback:
		return _permission_denied_response(request, 'You do not have permission to delete feedback.')

	redirect_url = request.POST.get('next') or reverse('development_hub')
	feedback = get_object_or_404(DevelopmentFeedback, pk=feedback_id)
	feedback_title = feedback.title
	feedback.delete()
	messages.success(request, f'Feedback "{feedback_title}" deleted successfully.')
	return redirect(redirect_url)


@login_required
def development_patch_notes(request):
	can_add_patch_notes = request.user.is_superuser or request.user.has_perm('core.add_patchnote')
	can_change_patch_notes = request.user.is_superuser or request.user.has_perm('core.change_patchnote')
	can_delete_patch_notes = request.user.is_superuser or request.user.has_perm('core.delete_patchnote')
	can_manage_patch_notes = can_add_patch_notes or can_change_patch_notes or can_delete_patch_notes

	if request.method == 'POST':
		if not can_add_patch_notes:
			return _permission_denied_response(request, 'You do not have permission to post patch notes.')

		patch_note_form = PatchNoteForm(request.POST, request.FILES)
		if patch_note_form.is_valid():
			patch_note = patch_note_form.save(commit=False)
			patch_note.created_by = request.user
			patch_note.save()
			patch_note_form.save_attachments(patch_note, uploaded_by=request.user)
			messages.success(request, 'Patch note posted successfully.')
			return redirect('development_patch_notes')
	else:
		patch_note_form = PatchNoteForm()

	patch_notes_queryset = PatchNote.objects.all().order_by('-published_at', '-created_at')
	if not can_manage_patch_notes:
		patch_notes_queryset = patch_notes_queryset.filter(is_published=True)

	patch_notes_page = Paginator(patch_notes_queryset, 7).get_page(request.GET.get('page'))
	patch_note_ids = [note.id for note in patch_notes_page.object_list]
	comments_by_note_id = {}
	attachments_by_note_id = {}
	reaction_counts_by_note_id = {}
	current_reaction_by_note_id = {}
	reaction_labels = dict(PatchNoteReaction.REACTION_CHOICES)
	if patch_note_ids:
		for attachment in PatchNoteAttachment.objects.filter(patch_note_id__in=patch_note_ids).order_by('created_at'):
			attachment_name = (attachment.file.name or '').split('/')[-1]
			lower_name = attachment_name.lower()
			file_kind = 'file'
			if lower_name.endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.svg')):
				file_kind = 'image'
			elif lower_name.endswith(('.mp4', '.webm', '.mov', '.avi', '.mkv', '.m4v')):
				file_kind = 'video'

			attachments_by_note_id.setdefault(attachment.patch_note_id, []).append(
				{
					'url': attachment.file.url,
					'name': attachment_name or 'attachment.file',
					'kind': file_kind,
				}
			)

		for comment in PatchNoteComment.objects.filter(patch_note_id__in=patch_note_ids).select_related('created_by').order_by('created_at'):
			comments_by_note_id.setdefault(comment.patch_note_id, []).append(comment)

		for reaction in PatchNoteReaction.objects.filter(patch_note_id__in=patch_note_ids):
			note_reactions = reaction_counts_by_note_id.setdefault(reaction.patch_note_id, {})
			note_reactions[reaction.reaction] = note_reactions.get(reaction.reaction, 0) + 1
			if reaction.created_by_id == request.user.id:
				current_reaction_by_note_id[reaction.patch_note_id] = reaction.reaction

	for note in patch_notes_page.object_list:
		note.attachments_for_display = attachments_by_note_id.get(note.id, [])
		note.comments_for_display = comments_by_note_id.get(note.id, [])
		note.current_user_reaction = current_reaction_by_note_id.get(note.id, '')
		note.can_edit = can_change_patch_notes or (note.created_by_id == request.user.id)
		note.can_delete = can_delete_patch_notes or (note.created_by_id == request.user.id)
		note.reaction_buttons = []
		note_reactions = reaction_counts_by_note_id.get(note.id, {})
		for reaction_key, reaction_label in PatchNoteReaction.REACTION_CHOICES:
			note.reaction_buttons.append(
				{
					'key': reaction_key,
					'label': reaction_labels.get(reaction_key, reaction_key.title()),
					'count': note_reactions.get(reaction_key, 0),
					'is_selected': reaction_key == note.current_user_reaction,
				}
			)

	context = {
		'patch_notes_page': patch_notes_page,
		'patch_notes_page_numbers': patch_notes_page.paginator.page_range,
		'can_manage_patch_notes': can_manage_patch_notes,
		'can_add_patch_notes': can_add_patch_notes,
		'patch_note_form': patch_note_form,
		'patch_note_comment_form': PatchNoteCommentForm(),
	}
	return render(request, 'core/development_patch_notes.html', context)


@login_required
@require_POST
def development_patch_note_update(request, patch_note_id):
	patch_note = get_object_or_404(PatchNote, pk=patch_note_id)
	can_change_patch_notes = request.user.is_superuser or request.user.has_perm('core.change_patchnote')
	if not (can_change_patch_notes or patch_note.created_by_id == request.user.id):
		return _permission_denied_response(request, 'You do not have permission to edit this patch note.')

	form = PatchNoteForm(request.POST, request.FILES, instance=patch_note)
	if form.is_valid():
		updated_patch_note = form.save()
		form.save_attachments(updated_patch_note, uploaded_by=request.user)
		messages.success(request, 'Patch note updated successfully.')
	else:
		messages.warning(request, 'Unable to update patch note. Please review the fields.')

	return redirect('development_patch_notes')


@login_required
@require_POST
def development_patch_note_delete(request, patch_note_id):
	patch_note = get_object_or_404(PatchNote, pk=patch_note_id)
	can_delete_patch_notes = request.user.is_superuser or request.user.has_perm('core.delete_patchnote')
	if not (can_delete_patch_notes or patch_note.created_by_id == request.user.id):
		return _permission_denied_response(request, 'You do not have permission to delete this patch note.')

	patch_title = patch_note.title
	patch_note.delete()
	messages.success(request, f'Patch note "{patch_title}" deleted.')
	return redirect('development_patch_notes')


@login_required
@require_POST
def development_patch_note_comment_add(request, patch_note_id):
	patch_note = get_object_or_404(PatchNote, pk=patch_note_id)
	if not patch_note.is_published and not (request.user.is_superuser or request.user.has_perm('core.change_patchnote')):
		return _permission_denied_response(request, 'You do not have permission to comment on this patch note.')
	can_manage_patch_notes = request.user.is_superuser or request.user.has_perm('core.add_patchnote')

	form = PatchNoteCommentForm(request.POST)
	if form.is_valid():
		comment = form.save(commit=False)
		comment.patch_note = patch_note
		comment.created_by = request.user
		comment.save()

		# Notify user commenters when an admin posts a reply on the same patch note.
		if can_manage_patch_notes:
			commenter_ids = list(
				PatchNoteComment.objects
				.filter(patch_note=patch_note)
				.exclude(created_by__isnull=True)
				.exclude(created_by=request.user)
				.values_list('created_by_id', flat=True)
				.distinct()
			)
			if commenter_ids:
				for target_user in User.objects.filter(id__in=commenter_ids):
					create_notification(
						target_user,
						title='Admin replied on patch note',
						message=f'An admin replied on patch note v{patch_note.version} - {patch_note.title}.',
						link_url=reverse('development_patch_notes'),
					)
		messages.success(request, 'Comment added to patch note.')
	else:
		messages.warning(request, 'Comment cannot be empty.')

	return redirect('development_patch_notes')


@login_required
@require_POST
def development_patch_note_toggle_like(request, patch_note_id):
	patch_note = get_object_or_404(PatchNote, pk=patch_note_id)
	if not patch_note.is_published and not (request.user.is_superuser or request.user.has_perm('core.change_patchnote')):
		return _permission_denied_response(request, 'You do not have permission to react to this patch note.')
	reaction_value = (request.POST.get('reaction') or 'like').strip().lower()
	allowed_reactions = {choice[0] for choice in PatchNoteReaction.REACTION_CHOICES}
	if reaction_value not in allowed_reactions:
		messages.error(request, 'Invalid reaction type.')
		return redirect('development_patch_notes')

	reaction = PatchNoteReaction.objects.filter(
		patch_note=patch_note,
		created_by=request.user,
	).first()

	if reaction and reaction.reaction == reaction_value:
		reaction.delete()
		messages.info(request, 'Reaction removed.')
	else:
		if reaction:
			reaction.reaction = reaction_value
			reaction.save(update_fields=['reaction'])
		else:
			PatchNoteReaction.objects.create(
				patch_note=patch_note,
				created_by=request.user,
				reaction=reaction_value,
			)
		messages.success(request, 'Reaction updated.')

	return redirect('development_patch_notes')


@login_required
@require_POST
def development_patch_note_comment_edit(request, comment_id):
	comment = get_object_or_404(PatchNoteComment.objects.select_related('created_by', 'patch_note'), pk=comment_id)
	can_manage_comments = request.user.is_superuser or request.user.has_perm('core.change_patchnotecomment')
	if not (can_manage_comments or comment.created_by_id == request.user.id):
		return _permission_denied_response(request, 'You do not have permission to edit this comment.')

	new_comment = (request.POST.get('comment') or '').strip()
	if not new_comment:
		messages.warning(request, 'Comment cannot be empty.')
		return redirect('development_patch_notes')

	comment.comment = new_comment
	comment.save(update_fields=['comment'])
	messages.success(request, 'Comment updated.')
	return redirect('development_patch_notes')


@login_required
@require_POST
def development_patch_note_comment_delete(request, comment_id):
	comment = get_object_or_404(PatchNoteComment.objects.select_related('created_by'), pk=comment_id)
	can_manage_patch_notes = request.user.is_superuser or request.user.has_perm('core.delete_patchnotecomment')
	if not (can_manage_patch_notes or comment.created_by_id == request.user.id):
		return _permission_denied_response(request, 'You do not have permission to delete this comment.')

	comment.delete()
	messages.success(request, 'Comment deleted.')
	return redirect('development_patch_notes')


@login_required
def profile_page(request):
	profile, _ = UserProfile.objects.get_or_create(user=request.user)
	if not request.session.get('presence_session_id'):
		_sync_presence_session(request, profile.status)
	role_names = list(request.user.groups.values_list('name', flat=True))
	department = role_names[0] if role_names else 'Not assigned'
	branch = profile.branch or 'Not assigned'
	presence_status = request.session.get('presence_status') or profile.status
	last_event_ms = request.session.get('presence_last_event_ms')
	last_activity_label = _format_last_activity_label(last_event_ms)

	context = {
		'profile': profile,
		'role_names': role_names,
		'department': department,
		'branch': branch,
		'presence_status': str(presence_status).title(),
		'last_activity_label': last_activity_label,
	}
	return render(request, 'core/profile.html', context)


@login_required
def users_quick_profile(request, user_id):
	managed_user = get_object_or_404(User.objects.select_related('profile').prefetch_related('groups'), pk=user_id)
	profile = getattr(managed_user, 'profile', None)

	full_name = managed_user.get_full_name() or managed_user.username
	avatar_url = ''
	if profile and profile.avatar:
		avatar_url = profile.avatar.url

	return JsonResponse(
		{
			'ok': True,
			'user': {
				'id': managed_user.id,
				'username': managed_user.username,
				'full_name': full_name,
				'email': managed_user.email or '-',
				'branch': profile.branch if profile and profile.branch else 'Not assigned',
				'status': profile.get_status_display() if profile else 'Active',
				'roles': [group.name for group in managed_user.groups.all()],
				'avatar_url': avatar_url,
				'avatar_initial': (full_name[:1] or managed_user.username[:1] or 'U').upper(),
			},
		}
	)


def lockout_notice(request):
	if request.user.is_authenticated:
		return redirect('dashboard')
	username_hint = (request.GET.get('u') or '').strip()
	return render(request, 'registration/lockout.html', {'username_hint': username_hint})


@login_required
def support_lockout_center(request):
	if not (request.user.is_superuser or request.user.has_perm('axes.view_accessattempt')):
		return _permission_denied_response(request, 'You do not have permission to view lockout records.')

	query = (request.GET.get('q') or '').strip()
	attempts = AccessAttempt.objects.all().order_by('-attempt_time')
	lockouts = AccessFailureLog.objects.filter(locked_out=True).order_by('-attempt_time')

	if query:
		attempts = attempts.filter(Q(username__icontains=query) | Q(ip_address__icontains=query))
		lockouts = lockouts.filter(Q(username__icontains=query) | Q(ip_address__icontains=query))

	if request.method == 'POST':
		if not (request.user.is_superuser or request.user.has_perm('axes.delete_accessattempt')):
			return _permission_denied_response(request, 'You do not have permission to unlock lockouts.')

		action_type = (request.POST.get('action_type') or 'manual').strip()
		if action_type == 'row_unlock':
			username = (request.POST.get('username') or '').strip() or None
			ip_address = (request.POST.get('ip_address') or '').strip() or None

			if not username and not ip_address:
				messages.error(request, 'Unlock failed: no username or IP provided for this row.')
				return redirect('support_lockout_center')

			reset_count = axes_reset(ip=ip_address, username=username)
			LoginEvent.objects.create(
				user=request.user,
				username_attempt=username or request.user.username,
				ip_address=ip_address,
				user_agent=request.META.get('HTTP_USER_AGENT', '')[:255],
				successful=True,
				reason='support_unlock',
			)

			messages.success(request, f'Row unlock processed. Cleared {reset_count} lockout record(s).')
			return redirect('support_lockout_center')

		form = LockoutResetForm(request.POST)
		if form.is_valid():
			username = (form.cleaned_data.get('username') or '').strip() or None
			ip_address = form.cleaned_data.get('ip_address')
			reset_count = axes_reset(ip=ip_address, username=username)

			if username or ip_address:
				LoginEvent.objects.create(
					user=request.user,
					username_attempt=username or request.user.username,
					ip_address=ip_address,
					user_agent=request.META.get('HTTP_USER_AGENT', '')[:255],
					successful=True,
					reason='support_unlock',
				)

			messages.success(request, f'Unlock processed. Cleared {reset_count} lockout record(s).')
			return redirect('support_lockout_center')
	else:
		form = LockoutResetForm()

	context = {
		'form': form,
		'attempts': attempts[:50],
		'lockouts': lockouts[:50],
		'query': query,
	}
	return render(request, 'core/lockout_support.html', context)


def _permission_denied_response(request, message='You do not have permission to perform this action.'):
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		return JsonResponse({'ok': False, 'message': message}, status=403)

	messages.error(request, message, extra_tags='permission-modal')
	referer = (request.META.get('HTTP_REFERER') or '').strip()
	if referer and url_has_allowed_host_and_scheme(referer, {request.get_host()}):
		return redirect(referer)
	return redirect('dashboard')


def _require_permission(request, perm_name):
	if request.user.is_superuser or request.user.has_perm(perm_name):
		return None
	return _permission_denied_response(request)


def _can_manage_company_internet_accounts(user):
	return user.is_superuser or user.has_perm('core.change_companyinternetaccount') or user.has_perm('core.view_companyinternetaccount')


def _get_unlocked_company_account_ids(request):
	payload = request.session.get(INTERNET_ACCOUNT_UNLOCK_SESSION_KEY) or {}
	if not isinstance(payload, dict):
		request.session[INTERNET_ACCOUNT_UNLOCK_SESSION_KEY] = {}
		request.session.modified = True
		return set()

	now_ts = timezone.now().timestamp()
	active_payload = {}
	for raw_id, expires_at in payload.items():
		try:
			account_id = int(raw_id)
			expires_value = float(expires_at)
		except (TypeError, ValueError):
			continue
		if expires_value > now_ts:
			active_payload[str(account_id)] = expires_value

	if active_payload != payload:
		request.session[INTERNET_ACCOUNT_UNLOCK_SESSION_KEY] = active_payload
		request.session.modified = True

	return {int(account_id) for account_id in active_payload.keys()}


def _mark_company_account_unlocked(request, account_id):
	payload = request.session.get(INTERNET_ACCOUNT_UNLOCK_SESSION_KEY) or {}
	if not isinstance(payload, dict):
		payload = {}
	payload[str(account_id)] = timezone.now().timestamp() + INTERNET_ACCOUNT_UNLOCK_TTL_SECONDS
	request.session[INTERNET_ACCOUNT_UNLOCK_SESSION_KEY] = payload
	request.session.modified = True


def _mark_company_account_locked(request, account_id):
	payload = request.session.get(INTERNET_ACCOUNT_UNLOCK_SESSION_KEY) or {}
	if not isinstance(payload, dict):
		request.session[INTERNET_ACCOUNT_UNLOCK_SESSION_KEY] = {}
		request.session.modified = True
		return

	account_key = str(account_id)
	if account_key in payload:
		payload.pop(account_key, None)
		request.session[INTERNET_ACCOUNT_UNLOCK_SESSION_KEY] = payload
		request.session.modified = True


def _can_access_all_clients(user):
	if user.is_superuser:
		return True
	return (
		user.has_perm('core.change_client')
		or user.has_perm('core.delete_client')
		or user.has_perm('core.approve_clientdeletionrequest')
	)


def _filter_clients_by_visibility(request, queryset=None):
	base_queryset = queryset if queryset is not None else Client.objects.all()
	if _can_access_all_clients(request.user):
		return base_queryset
	return base_queryset.filter(handled_by=request.user)


def _can_manage_fund_request_templates(user):
	return user.is_superuser or user.has_perm('core.add_fundrequesttemplate') or user.has_perm('core.change_fundrequesttemplate')


def _can_manage_liquidation_templates(user):
	return user.is_superuser or user.has_perm('core.add_liquidationtemplate') or user.has_perm('core.change_liquidationtemplate')


def _can_approve_fund_requests(user):
	return user.is_superuser or user.has_perm('core.change_fundrequest')


def _can_approve_liquidations(user):
	return user.is_superuser or user.has_perm('core.change_liquidation')


def _can_cancel_other_fund_requests(user):
	return user.is_superuser or user.has_perm('core.change_fundrequest')


def _fund_request_approvers_queryset():
	return (
		User.objects.filter(is_active=True)
		.filter(
			Q(is_superuser=True)
			| Q(user_permissions__content_type__app_label='core', user_permissions__codename='change_fundrequest')
			| Q(groups__permissions__content_type__app_label='core', groups__permissions__codename='change_fundrequest')
		)
		.distinct()
	)


def _notify_fund_request_approvers(fund_request):
	approval_link = reverse('fund_requests_list')
	requester_name = fund_request.requester_name or 'Unknown requester'
	total_label = f'PHP {_format_fund_request_amount(fund_request.total_amount)}'
	for approver in _fund_request_approvers_queryset():
		if fund_request.created_by_id and approver.pk == fund_request.created_by_id:
			continue
		create_notification(
			user=approver,
			title='Fund request approval needed',
			message=f'{requester_name} submitted a fund request for {total_label}.',
			link_url=approval_link,
		)


def _notify_fund_request_requester(fund_request):
	if not fund_request.created_by:
		return

	if fund_request.request_status == 'approved':
		title = 'Fund Request Approved'
		message = f'Your fund request was approved with serial number {fund_request.serial_number}.'
		link_url = reverse('fund_requests_list')
	elif fund_request.request_status == 'cancelled':
		title = 'Fund Request Cancelled'
		reason_suffix = f' Reason: {fund_request.decision_reason}' if fund_request.decision_reason else ''
		message = f'Your fund request was cancelled.{reason_suffix}'
		link_url = reverse('fund_requests_list')
	else:
		title = 'Fund Request Rejected'
		reason_suffix = f' Reason: {fund_request.decision_reason}' if fund_request.decision_reason else ''
		message = f'Your fund request was rejected.{reason_suffix}'
		link_url = f"{reverse('fund_requests_list')}?{urlencode({'rejected_request': fund_request.pk})}"

	create_notification(
		user=fund_request.created_by,
		title=title,
		message=message,
		link_url=link_url,
	)


def _fund_request_matches_auto_approve_rule(fund_request, rule):
	if not fund_request or not rule:
		return False

	requester_keyword = (rule.requester_keyword or '').strip()
	if requester_keyword and requester_keyword.lower() not in (fund_request.requester_name or '').lower():
		return False

	department_keyword = (rule.department_keyword or '').strip()
	if department_keyword and department_keyword.lower() not in (fund_request.department or '').lower():
		return False

	branch_keyword = (rule.branch_keyword or '').strip()
	if branch_keyword and branch_keyword.lower() not in (fund_request.branch or '').lower():
		return False

	if rule.request_date_from and (not fund_request.request_date or fund_request.request_date < rule.request_date_from):
		return False
	if rule.request_date_to and (not fund_request.request_date or fund_request.request_date > rule.request_date_to):
		return False

	try:
		total_amount = Decimal(str(fund_request.total_amount or 0))
	except (InvalidOperation, TypeError, ValueError):
		total_amount = Decimal('0')
	if rule.min_amount is not None and total_amount < rule.min_amount:
		return False
	if rule.max_amount is not None and total_amount > rule.max_amount:
		return False

	if rule.require_attachments and not fund_request.attachments.exists():
		return False
	return True


def _get_matching_auto_approve_rule_for_fund_request(fund_request):
	active_rules = FundRequestAutoApproveRule.objects.filter(is_active=True).order_by('-updated_at', '-created_at')
	for rule in active_rules:
		if _fund_request_matches_auto_approve_rule(fund_request, rule):
			return rule
	return None


def _parse_optional_amount(raw_value):
	raw_text = (raw_value or '').strip()
	if not raw_text:
		return None
	try:
		return Decimal(raw_text)
	except (InvalidOperation, TypeError, ValueError):
		return None


def _fund_request_template_extension(template_record):
	if not template_record or not getattr(template_record, 'file', None):
		return ''
	return Path(getattr(template_record.file, 'name', '') or '').suffix.lower()


def _format_fund_request_date(date_value):
	if not date_value:
		return ''
	return date_value.strftime('%B %d, %Y')


def _format_fund_request_item_date(date_value):
	if not date_value:
		return ''
	return date_value.strftime('%m/%d/%Y')


def _format_fund_request_amount(amount_value):
	try:
		amount = Decimal(str(amount_value or 0))
	except (InvalidOperation, ValueError, TypeError):
		amount = Decimal('0')
	return f'{amount:,.2f}'


def _build_fund_request_template_placeholders_from_values(
	*,
	serial_number='',
	requester_name='',
	request_date=None,
	department='',
	branch='',
	total_amount=0,
	prepared_by='-',
	created_at=None,
	template_name='',
	line_items=None,
):
	line_items = list(line_items or [])
	placeholders = {
		'{{ serial_number }}': serial_number or '',
		'{{ requester_name }}': requester_name or '',
		'{{ request_date }}': _format_fund_request_date(request_date),
		'{{ department }}': department or '',
		'{{ branch }}': branch or '',
		'{{ total_amount }}': _format_fund_request_amount(total_amount),
		'{{ total_amount_php }}': f'PHP {_format_fund_request_amount(total_amount)}',
		'{{ prepared_by }}': prepared_by or '-',
		'{{ created_at }}': timezone.localtime(created_at).strftime('%Y-%m-%d %H:%M') if created_at else '',
		'{{ template_name }}': template_name or '',
	}

	line_items_lines = []
	for index, item in enumerate(line_items, start=1):
		item_date = item.get('entry_date')
		item_particulars = item.get('particulars') or ''
		item_amount = item.get('amount') or 0
		item_date_label = _format_fund_request_item_date(item_date)
		placeholders[f'{{{{ item_{index}_date }}}}'] = item_date_label
		placeholders[f'{{{{ item_{index}_particulars }}}}'] = item_particulars
		placeholders[f'{{{{ item_{index}_amount }}}}'] = f'{item_amount:.2f}'
		placeholders[f'{{{{ item_{index}_amount_php }}}}'] = f'PHP {_format_fund_request_amount(item_amount)}'
		line_items_lines.append(f'{index}. {item_date_label} | {item_particulars} | PHP {_format_fund_request_amount(item_amount)}')

	for index in range(len(line_items) + 1, 21):
		placeholders[f'{{{{ item_{index}_date }}}}'] = ''
		placeholders[f'{{{{ item_{index}_particulars }}}}'] = ''
		placeholders[f'{{{{ item_{index}_amount }}}}'] = ''
		placeholders[f'{{{{ item_{index}_amount_php }}}}'] = ''

	placeholders['{{ line_items }}'] = '\n'.join(line_items_lines)
	placeholders['{{ line_items_table }}'] = '\n'.join(line_items_lines)
	return placeholders


def _build_fund_request_template_placeholders(fund_request):
	line_items = [
		{
			'entry_date': item.entry_date,
			'particulars': item.particulars,
			'amount': item.amount,
		}
		for item in fund_request.items.all()
	]
	prepared_by = '-'
	if fund_request.created_by:
		prepared_by = fund_request.created_by.get_full_name() or fund_request.created_by.username
	return _build_fund_request_template_placeholders_from_values(
		serial_number=fund_request.serial_number or '',
		requester_name=fund_request.requester_name or '',
		request_date=fund_request.request_date,
		department=fund_request.department or '',
		branch=fund_request.branch or '',
		total_amount=fund_request.total_amount or 0,
		prepared_by=prepared_by,
		created_at=fund_request.created_at,
		template_name=fund_request.template.name if fund_request.template else '',
		line_items=line_items,
	)


def _build_fund_request_line_items_context_from_values(line_items=None):
	context_items = []
	for index, item in enumerate(line_items or [], start=1):
		item_date = item.get('entry_date')
		item_amount = item.get('amount') or 0
		context_items.append(
			{
				'index': index,
				'entry_date': _format_fund_request_item_date(item_date),
				'particulars': item.get('particulars') or '',
				'amount': f'{item_amount:.2f}',
				'amount_php': f'PHP {_format_fund_request_amount(item_amount)}',
			}
		)
	return context_items


def _build_fund_request_line_items_context(fund_request):
	return _build_fund_request_line_items_context_from_values(
		[
			{
				'entry_date': item.entry_date,
				'particulars': item.particulars,
				'amount': item.amount,
			}
			for item in fund_request.items.all()
		]
	)


def _replace_line_item_block_placeholders(content, line_item):
	updated = content
	for key, value in line_item.items():
		updated = updated.replace(f'{{{{ {key} }}}}', escape(str(value), {'"': '&quot;', "'": '&apos;'}))
	return updated


def _shift_xlsx_row_numbers(block_content, row_offset):
	def replace_row_tag(match):
		original_row = int(match.group(2))
		return match.group(0).replace(f'r="{original_row}"', f'r="{original_row + row_offset}"', 1)

	def replace_cell_ref(match):
		column_ref = match.group(1)
		row_number = int(match.group(2))
		return f'r="{column_ref}{row_number + row_offset}"'

	updated = re.sub(r'<row\b([^>]*)\br="(\d+)"', replace_row_tag, block_content)
	updated = re.sub(r'r="([A-Z]+)(\d+)"', replace_cell_ref, updated)
	return updated


def _expand_dynamic_line_item_blocks(content, line_items, extension):
	block_pattern = re.compile(r'{{#line_items}}(.*?){{/line_items}}', re.DOTALL)

	def render_block(match):
		block_content = match.group(1)
		if not line_items:
			return ''

		if extension == '.xlsx':
			row_match = re.search(r'<row\b[^>]*\br="(\d+)"[^>]*>.*?</row>', block_content, re.DOTALL)
			base_row = int(row_match.group(1)) if row_match else None
			rendered_rows = []
			for index, line_item in enumerate(line_items):
				item_block = _replace_line_item_block_placeholders(block_content, line_item)
				if base_row is not None:
					item_block = _shift_xlsx_row_numbers(item_block, index)
				rendered_rows.append(item_block)
			return ''.join(rendered_rows)

		return ''.join(_replace_line_item_block_placeholders(block_content, line_item) for line_item in line_items)

	return block_pattern.sub(render_block, content)


def _replace_placeholders_in_text(content, placeholders, line_items=None, extension=''):
	if line_items is None:
		line_items = []

	updated = _expand_dynamic_line_item_blocks(content, line_items, extension)
	for key, value in placeholders.items():
		updated = updated.replace(key, escape(str(value), {'"': '&quot;', "'": '&apos;'}))
	return updated


def _render_fund_request_template_binary_from_template(template_record, placeholders, line_items, output_name):
	if not template_record or not getattr(template_record, 'file', None):
		return None

	extension = _fund_request_template_extension(template_record)
	if extension not in {'.docx', '.xlsx'}:
		return None

	with template_record.file.open('rb') as template_file:
		source_bytes = template_file.read()

	source_buffer = BytesIO(source_bytes)
	output_buffer = BytesIO()
	with zipfile.ZipFile(source_buffer, 'r') as source_zip, zipfile.ZipFile(output_buffer, 'w', zipfile.ZIP_DEFLATED) as target_zip:
		for zip_info in source_zip.infolist():
			file_bytes = source_zip.read(zip_info.filename)
			if zip_info.filename.endswith('.xml') or zip_info.filename.endswith('.rels'):
				try:
					text_content = file_bytes.decode('utf-8')
				except UnicodeDecodeError:
					target_zip.writestr(zip_info, file_bytes)
					continue
				replaced = _replace_placeholders_in_text(text_content, placeholders, line_items=line_items, extension=extension)
				target_zip.writestr(zip_info, replaced.encode('utf-8'))
			else:
				target_zip.writestr(zip_info, file_bytes)

	if extension == '.docx':
		content_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
	else:
		content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

	return {
		'content': output_buffer.getvalue(),
		'content_type': content_type,
		'filename': output_name,
		'template_record': template_record,
		'extension': extension,
	}


def _render_fund_request_template_binary(fund_request):
	template_record = fund_request.template
	if not template_record or not getattr(template_record, 'file', None):
		return None

	extension = _fund_request_template_extension(template_record)
	placeholders = _build_fund_request_template_placeholders(fund_request)
	line_items = _build_fund_request_line_items_context(fund_request)
	output_name = f'fund-request-{fund_request.serial_number}{extension}'
	return _render_fund_request_template_binary_from_template(template_record, placeholders, line_items, output_name)


def _build_sample_fund_request_preview_context(template_record):
	request_date = timezone.localdate()
	created_at = timezone.now()
	line_items = [
		{'entry_date': request_date, 'particulars': 'Transportation allowance', 'amount': 1250.00},
		{'entry_date': request_date, 'particulars': 'Client lunch meeting', 'amount': 1850.00},
		{'entry_date': request_date, 'particulars': 'Project supplies', 'amount': 2499.50},
	]
	total_amount = sum(item['amount'] for item in line_items)
	return {
		'sample_summary': {
			'serial_number': '2026-0001',
			'requester_name': 'Juan Dela Cruz',
			'request_date': _format_fund_request_date(request_date),
			'department': 'Operations',
			'branch': 'Main Branch',
			'prepared_by': 'Portal Demo User',
			'total_amount_php': f'PHP {_format_fund_request_amount(total_amount)}',
		},
		'placeholders': _build_fund_request_template_placeholders_from_values(
			serial_number='2026-0001',
			requester_name='Juan Dela Cruz',
			request_date=request_date,
			department='Operations',
			branch='Main Branch',
			total_amount=total_amount,
			prepared_by='Portal Demo User',
			created_at=created_at,
			template_name=template_record.name if template_record else '',
			line_items=line_items,
		),
		'line_items': _build_fund_request_line_items_context_from_values(line_items),
	}


def _build_fund_request_template_placeholder_guide():
	return [
		{
			'placeholder': '{{ serial_number }}',
			'description': 'Shows the approved fund request serial number (blank while pending).',
			'use_case': 'Use in the document header, title bar, or control number area.',
		},
		{
			'placeholder': '{{ requester_name }}',
			'description': 'Displays the employee or requester full name.',
			'use_case': 'Use beside labels like Requester, Requested By, or Name.',
		},
		{
			'placeholder': '{{ request_date }}',
			'description': 'Outputs the request date in `MMMM DD, YYYY` format (example: April 25, 2026).',
			'use_case': 'Use for the request date field in forms and approval sheets.',
		},
		{
			'placeholder': '{{ department }}',
			'description': 'Shows the selected department.',
			'use_case': 'Use in the requester details section or routing block.',
		},
		{
			'placeholder': '{{ branch }}',
			'description': 'Shows the selected branch or office.',
			'use_case': 'Use under department, office, or branch labels.',
		},
		{
			'placeholder': '{{ total_amount }}',
			'description': 'Outputs the computed total amount as a numeric value with thousands separators.',
			'use_case': 'Use inside formulas or cells that should not include the `PHP` prefix.',
		},
		{
			'placeholder': '{{ total_amount_php }}',
			'description': 'Outputs the computed total amount with the `PHP` currency prefix and thousands separators.',
			'use_case': 'Use for grand total labels in printed fund request forms.',
		},
		{
			'placeholder': '{{ prepared_by }}',
			'description': 'Shows the portal user who prepared or submitted the request.',
			'use_case': 'Use for signatures, footer summaries, or prepared-by blocks.',
		},
		{
			'placeholder': '{{ created_at }}',
			'description': 'Shows when the request record was created in the portal.',
			'use_case': 'Use in audit stamps, footer notes, or generated metadata.',
		},
		{
			'placeholder': '{{ template_name }}',
			'description': 'Outputs the current fund request template name.',
			'use_case': 'Use in document footers or internal reference labels.',
		},
		{
			'placeholder': '{{ line_items }}',
			'description': 'Creates a plain text multi-line summary of all line items.',
			'use_case': 'Use when the template only needs one paragraph or text box summary.',
		},
		{
			'placeholder': '{{ line_items_table }}',
			'description': 'Alias of `{{ line_items }}` that outputs the same multi-line summary text.',
			'use_case': 'Use in legacy templates that already use `line_items_table` naming.',
		},
		{
			'placeholder': '{{ item_1_date }}',
			'description': 'Outputs the first line item date in `MM/DD/YYYY` format. The same format works for `item_2_...` up to `item_20_...`.',
			'use_case': 'Use for fixed-row templates where each row is mapped manually.',
		},
		{
			'placeholder': '{{ item_1_particulars }}',
			'description': 'Outputs the first line item particulars. Repeat the number for additional fixed rows.',
			'use_case': 'Use in static Office templates with a known number of rows.',
		},
		{
			'placeholder': '{{ item_1_amount_php }}',
			'description': 'Outputs the first line item amount with the `PHP` prefix and thousands separators. Use `{{ item_1_amount }}` for numeric-only values.',
			'use_case': 'Use for fixed-row amount cells or static print layouts.',
		},
		{
			'placeholder': '{{#line_items}} ... {{/line_items}}',
			'description': 'Dynamic repeating block for uploaded `.docx` and `.xlsx` templates. Everything inside the block repeats once per line item.',
			'use_case': 'Use when the number of rows can change and the template should expand automatically.',
		},
		{
			'placeholder': '{{ entry_date }}',
			'description': 'Available only inside the `{{#line_items}}` block. Outputs the current row date in `MM/DD/YYYY` format.',
			'use_case': 'Use inside dynamic table rows for each expense date.',
		},
		{
			'placeholder': '{{ particulars }}',
			'description': 'Available only inside the `{{#line_items}}` block. Outputs the current row particulars.',
			'use_case': 'Use inside dynamic rows for item descriptions or expense details.',
		},
		{
			'placeholder': '{{ amount }}',
			'description': 'Available only inside the `{{#line_items}}` block. Outputs the current row amount as numeric-only.',
			'use_case': 'Use in numeric cells or formulas that should not include the `PHP` prefix.',
		},
		{
			'placeholder': '{{ amount_php }}',
			'description': 'Available only inside the `{{#line_items}}` block. Outputs the current row amount with the `PHP` prefix and thousands separators.',
			'use_case': 'Use inside dynamic rows when the amount should already be display-formatted.',
		},
	]


def _build_fund_request_template_quick_placeholder_guide():
	placeholder_guide = _build_fund_request_template_placeholder_guide()
	placeholder_map = {
		item['placeholder']: item
		for item in placeholder_guide
	}
	featured_placeholders = [
		'{{ serial_number }}',
		'{{ requester_name }}',
		'{{ request_date }}',
		'{{ department }}',
		'{{ branch }}',
		'{{ total_amount_php }}',
		'{{ prepared_by }}',
		'{{#line_items}} ... {{/line_items}}',
	]
	return [
		placeholder_map[placeholder]
		for placeholder in featured_placeholders
		if placeholder in placeholder_map
	]


def _ensure_active_fund_request_template():
	if FundRequestTemplate.objects.filter(is_active=True).exists():
		return
	fallback_template = FundRequestTemplate.objects.order_by('-updated_at', '-created_at').first()
	if not fallback_template:
		return
	fallback_template.is_active = True
	fallback_template.save(update_fields=['is_active'])


def _ensure_active_liquidation_template():
	if LiquidationTemplate.objects.filter(is_active=True).exists():
		return
	fallback_template = LiquidationTemplate.objects.order_by('-updated_at', '-created_at').first()
	if not fallback_template:
		return
	fallback_template.is_active = True
	fallback_template.save(update_fields=['is_active'])


def _build_text_pdf_bytes(lines):
	try:
		page_width = 1240
		page_height = 1754
		margin = 96
		line_height = 28
		lines_per_page = max(1, (page_height - (margin * 2)) // line_height)
		font = ImageFont.load_default()
		prepared_lines = []
		for raw_line in lines or []:
			text = str(raw_line or '').rstrip()
			if not text:
				prepared_lines.append('')
				continue
			prepared_lines.extend(textwrap.wrap(text, width=90) or [''])

		if not prepared_lines:
			prepared_lines = ['No preview content available.']

		pages = []
		for start in range(0, len(prepared_lines), lines_per_page):
			page_lines = prepared_lines[start:start + lines_per_page]
			canvas = Image.new('RGB', (page_width, page_height), 'white')
			draw = ImageDraw.Draw(canvas)
			current_y = margin
			for line in page_lines:
				draw.text((margin, current_y), line, fill='black', font=font)
				current_y += line_height
			pages.append(canvas)

		output = BytesIO()
		first_page, *other_pages = pages
		first_page.save(output, format='PDF', resolution=150.0, save_all=True, append_images=other_pages)
		return output.getvalue()
	except Exception:
		return None


def _build_notice_pdf_bytes(title, message_lines):
	lines = [str(title or 'Preview Notice'), '']
	lines.extend(message_lines or [])
	return _build_text_pdf_bytes(lines)


def _xlsx_shared_strings_from_archive(source_zip):
	try:
		shared_strings_xml = source_zip.read('xl/sharedStrings.xml')
	except KeyError:
		return []

	root = ET.fromstring(shared_strings_xml)
	shared_strings = []
	for string_item in root.findall('.//{*}si'):
		text_value = ''.join(node.text or '' for node in string_item.findall('.//{*}t'))
		shared_strings.append(text_value)
	return shared_strings


def _xlsx_sheet_targets_from_archive(source_zip):
	try:
		workbook_xml = source_zip.read('xl/workbook.xml')
		rels_xml = source_zip.read('xl/_rels/workbook.xml.rels')
	except KeyError:
		return []

	workbook_root = ET.fromstring(workbook_xml)
	rels_root = ET.fromstring(rels_xml)
	relationships = {}
	for relationship in rels_root.findall('.//{*}Relationship'):
		relationship_id = relationship.attrib.get('Id') or ''
		target = relationship.attrib.get('Target') or ''
		if not target:
			continue
		if target.startswith('/'):
			normalized_target = target.lstrip('/')
		elif target.startswith('xl/'):
			normalized_target = target
		else:
			normalized_target = f'xl/{target}'
		relationships[relationship_id] = normalized_target

	sheets = []
	for sheet in workbook_root.findall('.//{*}sheet'):
		sheet_name = sheet.attrib.get('name') or 'Sheet'
		relationship_id = (
			sheet.attrib.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')
			or sheet.attrib.get('{http://purl.oclc.org/ooxml/officeDocument/relationships}id')
			or ''
		)
		target = relationships.get(relationship_id)
		if target:
			sheets.append({'name': sheet_name, 'target': target})
	return sheets


def _xlsx_cell_display_value(cell_node, shared_strings):
	cell_type = cell_node.attrib.get('t') or ''
	if cell_type == 'inlineStr':
		return ''.join(node.text or '' for node in cell_node.findall('.//{*}t')).strip()

	value_node = cell_node.find('{*}v')
	if value_node is None:
		formula_node = cell_node.find('{*}f')
		return (formula_node.text or '').strip() if formula_node is not None and formula_node.text else ''

	raw_value = (value_node.text or '').strip()
	if not raw_value:
		return ''
	if cell_type == 's':
		try:
			return shared_strings[int(raw_value)]
		except (ValueError, IndexError):
			return raw_value
	if cell_type == 'b':
		return 'TRUE' if raw_value == '1' else 'FALSE'
	return raw_value


def _convert_xlsx_bytes_to_pdf(file_bytes, filename):
	try:
		lines = [f'Workbook Preview: {Path(filename or "workbook").name}', '']
		with zipfile.ZipFile(BytesIO(file_bytes), 'r') as source_zip:
			shared_strings = _xlsx_shared_strings_from_archive(source_zip)
			sheets = _xlsx_sheet_targets_from_archive(source_zip)
			if not sheets:
				return None

			for sheet_index, sheet in enumerate(sheets, start=1):
				lines.append(f'Sheet {sheet_index}: {sheet["name"]}')
				lines.append('')
				try:
					sheet_xml = source_zip.read(sheet['target'])
				except KeyError:
					lines.append('Sheet data could not be loaded.')
					lines.append('')
					continue

				sheet_root = ET.fromstring(sheet_xml)
				sheet_data = sheet_root.find('.//{*}sheetData')
				rendered_row_count = 0
				if sheet_data is not None:
					for row in sheet_data.findall('{*}row'):
						row_number = row.attrib.get('r') or str(rendered_row_count + 1)
						cells = []
						for cell in row.findall('{*}c'):
							cell_ref = cell.attrib.get('r') or ''
							cell_value = _xlsx_cell_display_value(cell, shared_strings)
							if cell_value:
								cells.append(f'{cell_ref}: {cell_value}')
						if cells:
							lines.append(f'Row {row_number} | ' + ' | '.join(cells))
							rendered_row_count += 1
						if rendered_row_count >= 120:
							lines.append('...')
							lines.append('Preview truncated after 120 non-empty rows.')
							break
				if rendered_row_count == 0:
					lines.append('No visible cell values found in this sheet.')
				lines.append('')

		return _build_text_pdf_bytes(lines)
	except Exception:
		return None


def _convert_docx_bytes_to_pdf(file_bytes, filename):
	try:
		lines = [f'Document Preview: {Path(filename or "document").name}', '']
		with zipfile.ZipFile(BytesIO(file_bytes), 'r') as source_zip:
			document_xml = source_zip.read('word/document.xml')
		document_root = ET.fromstring(document_xml)
		paragraph_count = 0
		for paragraph in document_root.findall('.//{*}p'):
			text_value = ''.join(node.text or '' for node in paragraph.findall('.//{*}t')).strip()
			if not text_value:
				continue
			lines.append(text_value)
			lines.append('')
			paragraph_count += 1
			if paragraph_count >= 180:
				lines.append('Preview truncated after 180 text paragraphs.')
				break
		if paragraph_count == 0:
			lines.append('No visible text content found in this document.')
		return _build_text_pdf_bytes(lines)
	except Exception:
		return None


@lru_cache(maxsize=1)
def _detect_microsoft_office_com_availability():
	powershell_path = shutil.which('powershell') or shutil.which('pwsh')
	if not powershell_path:
		return {'word': False, 'excel': False}

	script = r"""
$word = $false
$excel = $false

function Release-ComObject([object]$comObject) {
    if ($null -ne $comObject) {
        try {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
        } catch {}
    }
}

$wordApp = $null
try {
    $wordApp = New-Object -ComObject Word.Application
    $word = $true
    $wordApp.Quit()
} catch {} finally {
    if ($null -ne $wordApp) {
        try { $wordApp.Quit() } catch {}
    }
    Release-ComObject $wordApp
}

$excelApp = $null
try {
    $excelApp = New-Object -ComObject Excel.Application
    $excel = $true
    $excelApp.Quit()
} catch {} finally {
    if ($null -ne $excelApp) {
        try { $excelApp.Quit() } catch {}
    }
    Release-ComObject $excelApp
}

[GC]::Collect()
[GC]::WaitForPendingFinalizers()
Write-Output ("WORD=" + $(if ($word) { '1' } else { '0' }))
Write-Output ("EXCEL=" + $(if ($excel) { '1' } else { '0' }))
"""
	try:
		completed = subprocess.run(
			[powershell_path, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
			capture_output=True,
			text=True,
			check=False,
			timeout=20,
		)
	except Exception:
		return {'word': False, 'excel': False}

	if completed.returncode != 0:
		return {'word': False, 'excel': False}

	word_available = False
	excel_available = False
	for line in (completed.stdout or '').splitlines():
		normalized = line.strip().upper()
		if normalized == 'WORD=1':
			word_available = True
		elif normalized == 'EXCEL=1':
			excel_available = True

	return {'word': word_available, 'excel': excel_available}


def _office_conversion_backend_status(extension):
	word_supported_extensions = {'.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html'}
	excel_supported_extensions = {'.xls', '.xlsx', '.xlsm', '.xlsb', '.csv'}
	ms_apps = _detect_microsoft_office_com_availability()

	microsoft_office_available = False
	if extension in word_supported_extensions:
		microsoft_office_available = ms_apps.get('word', False)
	elif extension in excel_supported_extensions:
		microsoft_office_available = ms_apps.get('excel', False)
	else:
		microsoft_office_available = ms_apps.get('word', False) or ms_apps.get('excel', False)

	return {
		'microsoft_office': microsoft_office_available,
		'libreoffice': bool(shutil.which('libreoffice')),
		'soffice': bool(shutil.which('soffice')),
	}


def _convert_with_microsoft_office(file_bytes, safe_name, extension):
	powershell_path = shutil.which('powershell') or shutil.which('pwsh')
	if not powershell_path:
		return None

	word_supported_extensions = {'.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html'}
	excel_supported_extensions = {'.xls', '.xlsx', '.xlsm', '.xlsb', '.csv'}
	if extension not in word_supported_extensions and extension not in excel_supported_extensions:
		return None

	with tempfile.TemporaryDirectory(prefix='fund-template-preview-') as temp_dir:
		temp_path = Path(temp_dir)
		source_path = temp_path / safe_name
		pdf_path = temp_path / f'{source_path.stem}.pdf'
		source_path.write_bytes(file_bytes)

		def _ps_escape(value):
			return str(value).replace("'", "''")

		ps_script = f"""
$ErrorActionPreference = 'Stop'
$sourcePath = '{_ps_escape(source_path)}'
$targetPath = '{_ps_escape(pdf_path)}'
$extension = '{_ps_escape(extension)}'

function Release-ComObject([object]$comObject) {{
    if ($null -ne $comObject) {{
        try {{
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($comObject)
        }} catch {{}}
    }}
}}

if ($extension -in @('.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html')) {{
    $word = $null
    $document = $null
    try {{
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0
        $document = $word.Documents.Open($sourcePath, [ref]$false, [ref]$true)
        $document.ExportAsFixedFormat($targetPath, 17)
        $document.Close([ref]$false)
        $document = $null
        $word.Quit()
        $word = $null
    }} finally {{
        if ($null -ne $document) {{
            try {{ $document.Close([ref]$false) }} catch {{}}
        }}
        if ($null -ne $word) {{
            try {{ $word.Quit() }} catch {{}}
        }}
        Release-ComObject $document
        Release-ComObject $word
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }}
}} elseif ($extension -in @('.xls', '.xlsx', '.xlsm', '.xlsb', '.csv')) {{
    $excel = $null
    $workbook = $null
    try {{
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Open($sourcePath, 0, $true)
        $workbook.ExportAsFixedFormat(0, $targetPath)
        $workbook.Close($false)
        $workbook = $null
        $excel.Quit()
        $excel = $null
    }} finally {{
        if ($null -ne $workbook) {{
            try {{ $workbook.Close($false) }} catch {{}}
        }}
        if ($null -ne $excel) {{
            try {{ $excel.Quit() }} catch {{}}
        }}
        Release-ComObject $workbook
        Release-ComObject $excel
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }}
}} else {{
    throw "Unsupported extension for Microsoft Office conversion: $extension"
}}

if (-not (Test-Path -LiteralPath $targetPath)) {{
    throw "Microsoft Office did not produce a PDF output."
}}
"""
		completed = subprocess.run(
			[powershell_path, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
			capture_output=True,
			text=True,
			check=False,
		)
		if completed.returncode == 0 and pdf_path.exists():
			return pdf_path.read_bytes()
	return None


def _convert_with_libreoffice_command(file_bytes, safe_name, command_name):
	command_path = shutil.which(command_name)
	if not command_path:
		return None

	with tempfile.TemporaryDirectory(prefix='fund-template-preview-') as temp_dir:
		temp_path = Path(temp_dir)
		source_path = temp_path / safe_name
		pdf_path = temp_path / f'{source_path.stem}.pdf'
		profile_path = temp_path / 'libreoffice-profile'
		source_path.write_bytes(file_bytes)
		profile_uri = profile_path.resolve().as_uri()
		command = [
			command_path,
			'--headless',
			f'-env:UserInstallation={profile_uri}',
			'--convert-to',
			'pdf',
			'--outdir',
			str(temp_path),
			str(source_path),
		]
		completed = subprocess.run(command, capture_output=True, text=True, check=False)
		if completed.returncode == 0 and pdf_path.exists():
			return pdf_path.read_bytes()
	return None


def _convert_with_libreoffice(file_bytes, safe_name):
	return _convert_with_libreoffice_command(file_bytes, safe_name, 'libreoffice')


def _convert_with_soffice(file_bytes, safe_name):
	return _convert_with_libreoffice_command(file_bytes, safe_name, 'soffice')


def _convert_office_bytes_to_pdf(file_bytes, filename, allow_structured_preview_fallback=False):
	safe_name = Path(filename or 'preview').name or 'preview'
	extension = Path(safe_name).suffix.lower()
	backend_status = _office_conversion_backend_status(extension)
	pdf_bytes = None

	# Enforce strict priority order: Microsoft Office -> libreoffice -> soffice.
	# Attempt Microsoft Office first for supported document extensions even when the
	# availability probe is uncertain, then fall back to libreoffice/soffice.
	word_supported_extensions = {'.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html'}
	excel_supported_extensions = {'.xls', '.xlsx', '.xlsm', '.xlsb', '.csv'}
	if extension in word_supported_extensions or extension in excel_supported_extensions:
		pdf_bytes = _convert_with_microsoft_office(file_bytes, safe_name, extension)
	if not pdf_bytes and backend_status['libreoffice']:
		pdf_bytes = _convert_with_libreoffice(file_bytes, safe_name)
	if not pdf_bytes and backend_status['soffice']:
		pdf_bytes = _convert_with_soffice(file_bytes, safe_name)
	if pdf_bytes:
		return pdf_bytes

	if not allow_structured_preview_fallback:
		return None

	if extension == '.xlsx':
		return _convert_xlsx_bytes_to_pdf(file_bytes, safe_name)
	if extension == '.docx':
		return _convert_docx_bytes_to_pdf(file_bytes, safe_name)
	return None


def _render_html_bytes_to_pdf(html_bytes, filename='fund-request.html'):
	return _convert_office_bytes_to_pdf(html_bytes, filename, allow_structured_preview_fallback=False)


def _normalize_image_for_pdf(source_image):
	normalized = ImageOps.exif_transpose(source_image)
	if normalized.mode in {'RGBA', 'LA'} or (normalized.mode == 'P' and 'transparency' in normalized.info):
		rgba_image = normalized.convert('RGBA')
		background = Image.new('RGB', rgba_image.size, 'white')
		background.paste(rgba_image, mask=rgba_image.getchannel('A'))
		return background
	return normalized.convert('RGB')


def _build_fund_request_attachments_pdf_bytes(attachments):
	attachment_list = [attachment for attachment in attachments if getattr(attachment, 'image', None)]
	if not attachment_list:
		return None

	page_width = 1240
	page_height = 1754
	page_margin = 52
	item_gap = 22
	content_width = page_width - (page_margin * 2)
	content_height = page_height - (page_margin * 2)
	half_width = max(1, (content_width - item_gap) // 2)
	half_max_height = max(1, int(content_height * 0.62))
	wide_aspect_threshold = 1.55
	resample = Image.Resampling.LANCZOS if hasattr(Image, 'Resampling') else Image.LANCZOS
	pages = []
	current_page = None
	cursor_x = page_margin
	cursor_y = page_margin
	row_height = 0
	items_on_page = 0

	def start_page():
		nonlocal current_page, cursor_x, cursor_y, row_height, items_on_page
		current_page = Image.new('RGB', (page_width, page_height), 'white')
		cursor_x = page_margin
		cursor_y = page_margin
		row_height = 0
		items_on_page = 0

	def commit_page():
		nonlocal current_page
		if current_page is not None and items_on_page > 0:
			pages.append(current_page)
		current_page = None

	for attachment in attachment_list:
		try:
			if current_page is None:
				start_page()

			with attachment.image.open('rb') as image_file:
				with Image.open(image_file) as source_image:
					normalized = _normalize_image_for_pdf(source_image)
					source_width, source_height = normalized.size
					if source_width <= 0 or source_height <= 0:
						continue

					aspect_ratio = source_width / max(source_height, 1)
					use_full_width = aspect_ratio >= wide_aspect_threshold
					target_width = content_width if use_full_width else half_width
					target_max_height = content_height if use_full_width else half_max_height
					scale = min(target_width / source_width, target_max_height / source_height, 1.0)
					rendered_width = max(1, int(source_width * scale))
					rendered_height = max(1, int(source_height * scale))
					if scale < 1.0:
						rendered_image = normalized.resize((rendered_width, rendered_height), resample=resample)
					else:
						rendered_image = normalized.copy()

					placed = False
					while not placed:
						if cursor_x != page_margin and (cursor_x + rendered_width) > (page_margin + content_width):
							cursor_x = page_margin
							cursor_y += row_height + item_gap
							row_height = 0

						if (cursor_y + rendered_height) > (page_margin + content_height):
							commit_page()
							start_page()
							continue

						current_page.paste(rendered_image, (cursor_x, cursor_y))
						items_on_page += 1

						if use_full_width:
							cursor_x = page_margin
							cursor_y += max(row_height, rendered_height) + item_gap
							row_height = 0
						else:
							cursor_x += rendered_width + item_gap
							row_height = max(row_height, rendered_height)
						placed = True
		except Exception:
			# Skip unreadable attachments so valid images are still appended.
			continue

	commit_page()
	if not pages:
		return None

	output = BytesIO()
	first_page, *remaining_pages = pages
	first_page.save(
		output,
		format='PDF',
		resolution=150.0,
		save_all=True,
		append_images=remaining_pages,
	)
	return output.getvalue()


def _merge_pdf_parts(pdf_parts):
	valid_parts = [part for part in pdf_parts if part]
	if not valid_parts:
		return None
	if len(valid_parts) == 1:
		return valid_parts[0]

	if PdfReader and PdfWriter:
		try:
			writer = PdfWriter()
			for content in valid_parts:
				reader = PdfReader(BytesIO(content))
				for page in reader.pages:
					writer.add_page(page)
			output = BytesIO()
			writer.write(output)
			return output.getvalue()
		except Exception:
			pass

	pdfunite_path = shutil.which('pdfunite')
	if not pdfunite_path:
		return None

	with tempfile.TemporaryDirectory(prefix='fund-request-pdf-merge-') as temp_dir:
		temp_path = Path(temp_dir)
		input_paths = []
		for index, content in enumerate(valid_parts, start=1):
			part_path = temp_path / f'part-{index:03d}.pdf'
			part_path.write_bytes(content)
			input_paths.append(part_path)

		output_path = temp_path / 'merged.pdf'
		command = [pdfunite_path, *[str(path) for path in input_paths], str(output_path)]
		completed = subprocess.run(command, capture_output=True, text=True, check=False)
		if completed.returncode != 0 or not output_path.exists():
			return None
		return output_path.read_bytes()


def _build_fund_request_base_pdf_payload(fund_request, allow_structured_preview_fallback=False):
	template_record = fund_request.template
	template_extension = _fund_request_template_extension(template_record)

	if template_record and getattr(template_record, 'file', None):
		if template_extension == '.pdf':
			with template_record.file.open('rb') as template_file:
				return {
					'content': template_file.read(),
					'filename': f'fund-request-{fund_request.serial_number or fund_request.pk}.pdf',
					'source': 'template_pdf',
				}

		rendered_template = _render_fund_request_template_binary(fund_request)
		if rendered_template:
			pdf_bytes = _convert_office_bytes_to_pdf(
				rendered_template['content'],
				rendered_template['filename'],
				allow_structured_preview_fallback=allow_structured_preview_fallback,
			)
			if pdf_bytes:
				return {
					'content': pdf_bytes,
					'filename': f'{Path(rendered_template["filename"]).stem}.pdf',
					'source': 'template_generated_pdf',
				}

		if template_extension in {'.doc', '.xls'}:
			with template_record.file.open('rb') as template_file:
				pdf_bytes = _convert_office_bytes_to_pdf(
					template_file.read(),
					Path(template_record.file.name).name,
					allow_structured_preview_fallback=allow_structured_preview_fallback,
				)
			if pdf_bytes:
				return {
					'content': pdf_bytes,
					'filename': f'{Path(template_record.file.name).stem}.pdf',
					'source': 'template_converted_pdf',
				}

	content = render_to_string(
		'core/fund_request_document_pdf.html',
		{
			'fund_request': fund_request,
			'line_items': fund_request.items.all(),
			'template_record': fund_request.template,
			'template_extension': template_extension,
		},
	)
	pdf_bytes = _render_html_bytes_to_pdf(content.encode('utf-8'), f'fund-request-{fund_request.serial_number or fund_request.pk}.html')
	if not pdf_bytes:
		prepared_by = '-'
		if fund_request.created_by:
			prepared_by = fund_request.created_by.get_full_name() or fund_request.created_by.username
		summary_lines = [
			f'Serial Number: {fund_request.serial_number or "For Approval"}',
			f'Requester Name: {fund_request.requester_name or "-"}',
			f'Request Date: {_format_fund_request_date(fund_request.request_date) or "-"}',
			f'Department: {fund_request.department or "-"}',
			f'Branch: {fund_request.branch or "-"}',
			f'Prepared By: {prepared_by}',
			f'Total Amount: PHP {_format_fund_request_amount(fund_request.total_amount)}',
			'',
			'Line Items:',
		]
		for index, line_item in enumerate(fund_request.items.all(), start=1):
			line_date = _format_fund_request_item_date(line_item.entry_date) or '-'
			summary_lines.append(
				f'{index}. {line_date} | {line_item.particulars} | PHP {_format_fund_request_amount(line_item.amount)}'
			)
		if not fund_request.items.exists():
			summary_lines.append('No line items recorded.')
		pdf_bytes = _build_notice_pdf_bytes('Fund Request Document Summary', summary_lines)
		if not pdf_bytes:
			return None
		return {
			'content': pdf_bytes,
			'filename': f'fund-request-{fund_request.serial_number or fund_request.pk}.pdf',
			'source': 'generated_summary_pdf',
		}

	return {
		'content': pdf_bytes,
		'filename': f'fund-request-{fund_request.serial_number or fund_request.pk}.pdf',
		'source': 'generated_pdf',
	}


def _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=False):
	base_payload = _build_fund_request_base_pdf_payload(
		fund_request,
		allow_structured_preview_fallback=allow_structured_preview_fallback,
	)
	if not base_payload:
		return None

	attachments_pdf = _build_fund_request_attachments_pdf_bytes(fund_request.attachments.all())
	merged_pdf = _merge_pdf_parts([base_payload['content'], attachments_pdf]) or base_payload['content']
	return {
		'content': merged_pdf,
		'filename': base_payload['filename'],
		'source': base_payload['source'],
		'has_image_attachments': bool(attachments_pdf),
	}


def _build_fund_request_client_side_conversion_payload(fund_request):
	template_record = getattr(fund_request, 'template', None)
	template_extension = _fund_request_template_extension(template_record)
	if template_extension not in {'.docx', '.xlsx'}:
		return None

	rendered_template_payload = _build_fund_request_rendered_template_payload(fund_request)
	if rendered_template_payload and Path(rendered_template_payload['filename']).suffix.lower() == template_extension:
		source_bytes = rendered_template_payload['content']
		source_filename = rendered_template_payload['filename']
	else:
		if not template_record or not getattr(template_record, 'file', None):
			return None
		with template_record.file.open('rb') as template_file:
			source_bytes = template_file.read()
		source_filename = Path(template_record.file.name).name or f'fund-request-client-source{template_extension}'

	if not source_bytes:
		return None

	return {
		'extension': template_extension,
		'filename': source_filename,
		'content_b64': base64.b64encode(source_bytes).decode('ascii'),
	}


def _build_fund_request_rendered_template_payload(fund_request):
	rendered_template = _render_fund_request_template_binary(fund_request)
	if not rendered_template:
		return None

	return {
		'content': rendered_template['content'],
		'filename': rendered_template['filename'],
		'content_type': rendered_template['content_type'],
		'source': 'template_generated_file',
	}


def _build_fund_request_template_file_payload(fund_request):
	template_record = fund_request.template
	if not template_record or not getattr(template_record, 'file', None):
		return None

	rendered_payload = _build_fund_request_rendered_template_payload(fund_request)
	if rendered_payload:
		return rendered_payload

	template_extension = _fund_request_template_extension(template_record)
	content_type_map = {
		'.pdf': 'application/pdf',
		'.doc': 'application/msword',
		'.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
		'.xls': 'application/vnd.ms-excel',
		'.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
	}
	with template_record.file.open('rb') as template_file:
		return {
			'content': template_file.read(),
			'filename': Path(template_record.file.name).name or f'fund-request-template{template_extension or ""}',
			'content_type': content_type_map.get(template_extension, 'application/octet-stream'),
			'source': 'template_original_file',
		}


def _build_template_preview_pdf_payload(template_record):
	if not template_record or not getattr(template_record, 'file', None):
		return None

	extension = _fund_request_template_extension(template_record)
	with template_record.file.open('rb') as template_file:
		original_bytes = template_file.read()

	if extension == '.pdf':
		return {
			'content': original_bytes,
			'filename': f'{Path(template_record.file.name).stem or "fund-request-template"}-preview.pdf',
			'mode': 'original_pdf',
		}

	if extension in {'.docx', '.xlsx'}:
		sample_context = _build_sample_fund_request_preview_context(template_record)
		rendered_template = _render_fund_request_template_binary_from_template(
			template_record,
			sample_context['placeholders'],
			sample_context['line_items'],
			f'{Path(template_record.file.name).stem or "fund-request-template"}-filled{extension}',
		)
		if rendered_template:
			pdf_bytes = _convert_office_bytes_to_pdf(
				rendered_template['content'],
				rendered_template['filename'],
				allow_structured_preview_fallback=True,
			)
			if pdf_bytes:
				return {
					'content': pdf_bytes,
					'filename': f'{Path(rendered_template["filename"]).stem}.pdf',
					'mode': 'filled_preview',
				}

	if extension in {'.doc', '.docx', '.xls', '.xlsx'}:
		pdf_bytes = _convert_office_bytes_to_pdf(
			original_bytes,
			Path(template_record.file.name).name,
			allow_structured_preview_fallback=True,
		)
		if pdf_bytes:
			return {
				'content': pdf_bytes,
				'filename': f'{Path(template_record.file.name).stem or "fund-request-template"}-preview.pdf',
				'mode': 'converted_original',
			}

	return None


def _build_fund_request_template_preview_page_context(template_record, show_template_page_link=False):
	sample_context = _build_sample_fund_request_preview_context(template_record)
	template_extension = ''
	preview_mode = 'no_template'
	preview_pdf_url = ''
	if template_record:
		template_extension = _fund_request_template_extension(template_record)
		if template_extension == '.pdf':
			preview_mode = 'original_pdf'
		elif template_extension in {'.docx', '.xlsx'}:
			preview_mode = 'filled_preview'
		elif template_extension in {'.doc', '.xls'}:
			preview_mode = 'converted_original'
		else:
			preview_mode = 'unavailable'
		preview_pdf_url = reverse('fund_request_template_preview_pdf', args=[template_record.pk])

	return {
		'template_record': template_record,
		'template_extension': template_extension,
		'placeholder_guide': _build_fund_request_template_placeholder_guide(),
		'preview_pdf_url': preview_pdf_url,
		'preview_mode': preview_mode,
		'sample_summary': sample_context['sample_summary'],
		'show_template_page_link': show_template_page_link and bool(template_record),
	}


def _build_liquidation_line_items_context_from_values(line_items=None):
	context_items = []
	for index, item in enumerate(line_items or [], start=1):
		item_date = item.get('entry_date')
		item_amount = item.get('amount') or 0
		context_items.append(
			{
				'index': index,
				'entry_date': _format_fund_request_item_date(item_date),
				'entry_date_long': _format_fund_request_date(item_date),
				'fund_form_no': item.get('fund_form_no') or '',
				'description': item.get('description') or '',
				'amount': f'{item_amount:.2f}',
				'amount_php': f'PHP {_format_fund_request_amount(item_amount)}',
			}
		)
	return context_items


def _build_liquidation_line_items_context(liquidation):
	return _build_liquidation_line_items_context_from_values(
		[
			{
				'entry_date': item.entry_date,
				'fund_form_no': item.fund_form_no,
				'description': item.description,
				'amount': item.amount,
			}
			for item in liquidation.items.all()
		]
	)


def _build_liquidation_template_placeholders(liquidation):
	line_items = [
		{
			'entry_date': item.entry_date,
			'fund_form_no': item.fund_form_no,
			'description': item.description,
			'amount': item.amount,
		}
		for item in liquidation.items.all()
	]
	line_items_text_lines = [
		f'{index}. {_format_fund_request_item_date(item.get("entry_date"))} | {item.get("fund_form_no") or "-"} | {item.get("description") or "-"} | PHP {_format_fund_request_amount(item.get("amount") or 0)}'
		for index, item in enumerate(line_items, start=1)
	]
	if not line_items_text_lines:
		line_items_text_lines.append('No line items selected.')

	amount_requested = Decimal(liquidation.amount_requested or 0)
	amount_returned_or_over = Decimal(liquidation.amount_returned_or_over or 0)
	is_over = (liquidation.returned_or_over_type or '').lower() == 'over'
	computed_amount = (amount_requested + amount_returned_or_over) if is_over else (amount_requested - amount_returned_or_over)

	placeholders = {
		'{{ control_number }}': liquidation.control_number or '',
		'{{ name }}': liquidation.name or '',
		'{{ liquidation_date }}': _format_fund_request_date(liquidation.liquidation_date),
		'{{ liquidation_date_mmddyyyy }}': _format_fund_request_item_date(liquidation.liquidation_date),
		'{{ branch }}': liquidation.branch or '',
		'{{ position }}': liquidation.position or '',
		'{{ total_amount }}': _format_fund_request_amount(liquidation.total_amount),
		'{{ total_amount_php }}': f'PHP {_format_fund_request_amount(liquidation.total_amount)}',
		'{{ amount_requested }}': _format_fund_request_amount(liquidation.amount_requested),
		'{{ amount_requested_php }}': f'PHP {_format_fund_request_amount(liquidation.amount_requested)}',
		'{{ returned_or_over_type }}': liquidation.get_returned_or_over_type_display() if hasattr(liquidation, 'get_returned_or_over_type_display') else (liquidation.returned_or_over_type or ''),
		'{{ amount_returned_or_over }}': _format_fund_request_amount(liquidation.amount_returned_or_over),
		'{{ amount_returned_or_over_php }}': f'PHP {_format_fund_request_amount(liquidation.amount_returned_or_over)}',
		'{{ computed_amount }}': _format_fund_request_amount(computed_amount),
		'{{ computed_amount_php }}': f'PHP {_format_fund_request_amount(computed_amount)}',
		'{{ requested_by }}': liquidation.requested_by_name or '',
		'{{ template_name }}': liquidation.template.name if liquidation.template else '',
		'{{ line_items }}': '\n'.join(line_items_text_lines),
		'{{ line_items_table }}': '\n'.join(line_items_text_lines),
	}

	for index, item in enumerate(line_items, start=1):
		item_date = item.get('entry_date')
		item_amount = item.get('amount') or 0
		placeholders[f'{{{{ item_{index}_entry_date }}}}'] = _format_fund_request_item_date(item_date)
		placeholders[f'{{{{ item_{index}_entry_date_long }}}}'] = _format_fund_request_date(item_date)
		placeholders[f'{{{{ item_{index}_fund_form_no }}}}'] = item.get('fund_form_no') or ''
		placeholders[f'{{{{ item_{index}_description }}}}'] = item.get('description') or ''
		placeholders[f'{{{{ item_{index}_amount }}}}'] = _format_fund_request_amount(item_amount)
		placeholders[f'{{{{ item_{index}_amount_php }}}}'] = f'PHP {_format_fund_request_amount(item_amount)}'

	for index in range(len(line_items) + 1, 21):
		placeholders[f'{{{{ item_{index}_entry_date }}}}'] = ''
		placeholders[f'{{{{ item_{index}_entry_date_long }}}}'] = ''
		placeholders[f'{{{{ item_{index}_fund_form_no }}}}'] = ''
		placeholders[f'{{{{ item_{index}_description }}}}'] = ''
		placeholders[f'{{{{ item_{index}_amount }}}}'] = ''
		placeholders[f'{{{{ item_{index}_amount_php }}}}'] = ''

	return placeholders


def _build_liquidation_template_placeholder_guide():
	return [
		{
			'placeholder': '{{ control_number }}',
			'description': 'Shows the liquidation control number.',
			'use_case': 'Use in document headers and control reference blocks.',
		},
		{
			'placeholder': '{{ name }}',
			'description': 'Displays the liquidation name.',
			'use_case': 'Use for the main title or prepared-by name section.',
		},
		{
			'placeholder': '{{ liquidation_date }}',
			'description': 'Outputs liquidation date in `MMMM DD, YYYY` format.',
			'use_case': 'Use in the date field of the template.',
		},
		{
			'placeholder': '{{ liquidation_date_mmddyyyy }}',
			'description': 'Outputs liquidation date in `MM/DD/YYYY` format.',
			'use_case': 'Use when your template date fields require numeric month/day format.',
		},
		{
			'placeholder': '{{ branch }}',
			'description': 'Shows the selected branch.',
			'use_case': 'Use under office/branch labels.',
		},
		{
			'placeholder': '{{ position }}',
			'description': 'Shows the selected position.',
			'use_case': 'Use beside designation/role labels.',
		},
		{
			'placeholder': '{{ requested_by }}',
			'description': 'Shows the Requested By field value.',
			'use_case': 'Use in signature and accountability sections.',
		},
		{
			'placeholder': '{{ returned_or_over_type }}',
			'description': 'Shows `Returned` or `Over` based on the selected option.',
			'use_case': 'Use in liquidation summary labels and totals section.',
		},
		{
			'placeholder': '{{ amount_requested }}',
			'description': 'Outputs amount requested as numeric-only.',
			'use_case': 'Use in numeric cells or formulas (no currency prefix).',
		},
		{
			'placeholder': '{{ amount_requested_php }}',
			'description': 'Outputs amount requested with `PHP` prefix.',
			'use_case': 'Use in display totals with formatted currency text.',
		},
		{
			'placeholder': '{{ amount_returned_or_over }}',
			'description': 'Outputs returned/over amount as numeric-only.',
			'use_case': 'Use in numeric cells or formulas (no currency prefix).',
		},
		{
			'placeholder': '{{ amount_returned_or_over_php }}',
			'description': 'Outputs returned/over amount with `PHP` prefix.',
			'use_case': 'Use in display totals with formatted currency text.',
		},
		{
			'placeholder': '{{ computed_amount }}',
			'description': 'Computed amount based on selection: `Amount Requested - Returned` or `Amount Requested + Over`.',
			'use_case': 'Use in numeric result cells that should not include `PHP` prefix.',
		},
		{
			'placeholder': '{{ computed_amount_php }}',
			'description': 'Computed amount with `PHP` prefix based on returned/over type.',
			'use_case': 'Use for final liquidation amount display in printable templates.',
		},
		{
			'placeholder': '{{ total_amount }}',
			'description': 'Outputs line-item total as numeric-only.',
			'use_case': 'Use for arithmetic formulas or numeric table totals.',
		},
		{
			'placeholder': '{{ total_amount_php }}',
			'description': 'Outputs line-item total with `PHP` prefix.',
			'use_case': 'Use for printed totals and grand total labels.',
		},
		{
			'placeholder': '{{ template_name }}',
			'description': 'Outputs the selected liquidation template name.',
			'use_case': 'Use in footer metadata or internal reference section.',
		},
		{
			'placeholder': '{{ line_items }}',
			'description': 'Outputs all selected line items as plain multi-line text.',
			'use_case': 'Use in text areas when you need summary rows only.',
		},
		{
			'placeholder': '{{ line_items_table }}',
			'description': 'Alias of `{{ line_items }}` with same output.',
			'use_case': 'Use for legacy templates using `line_items_table` naming.',
		},
		{
			'placeholder': '{{ item_1_entry_date }}',
			'description': 'Outputs first selected item date in `MM/DD/YYYY` format. Repeat number for `item_2_...` to `item_20_...`.',
			'use_case': 'Use in fixed-row templates where rows are manually mapped.',
		},
		{
			'placeholder': '{{ item_1_entry_date_long }}',
			'description': 'Outputs first selected item date in `MMMM DD, YYYY` format.',
			'use_case': 'Use for fixed-row templates requiring long-form dates.',
		},
		{
			'placeholder': '{{ item_1_fund_form_no }}',
			'description': 'Outputs first selected item fund form number.',
			'use_case': 'Use in fixed-row templates for source reference columns.',
		},
		{
			'placeholder': '{{ item_1_description }}',
			'description': 'Outputs first selected item description.',
			'use_case': 'Use in fixed-row templates for particulars/description columns.',
		},
		{
			'placeholder': '{{ item_1_amount_php }}',
			'description': 'Outputs first selected item amount with `PHP` prefix. Use `{{ item_1_amount }}` for numeric-only.',
			'use_case': 'Use in fixed-row amount cells or printable totals.',
		},
		{
			'placeholder': '{{#line_items}} ... {{/line_items}}',
			'description': 'Dynamic repeating block for `.docx` and `.xlsx` templates. Content inside repeats per selected line item.',
			'use_case': 'Use when row count is variable and should expand automatically.',
		},
		{
			'placeholder': '{{ entry_date }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row date (`MM/DD/YYYY`).',
			'use_case': 'Use in the Date column of dynamic row blocks.',
		},
		{
			'placeholder': '{{ entry_date_long }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row date (`MMMM DD, YYYY`).',
			'use_case': 'Use when dynamic row dates need long text format.',
		},
		{
			'placeholder': '{{ fund_form_no }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row fund form number.',
			'use_case': 'Use in fund form/control number columns.',
		},
		{
			'placeholder': '{{ description }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row description.',
			'use_case': 'Use in particulars/description columns.',
		},
		{
			'placeholder': '{{ amount }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row amount as numeric-only.',
			'use_case': 'Use in formula cells that should not include `PHP` prefix.',
		},
		{
			'placeholder': '{{ amount_php }}',
			'description': 'Available only inside `{{#line_items}}` block. Current row amount with `PHP` prefix.',
			'use_case': 'Use in display-formatted amount cells.',
		},
	]


def _render_liquidation_template_binary(liquidation):
	template_record = liquidation.template
	if not template_record or not getattr(template_record, 'file', None):
		return None

	extension = _fund_request_template_extension(template_record)
	placeholders = _build_liquidation_template_placeholders(liquidation)
	line_items = _build_liquidation_line_items_context(liquidation)
	control_label = liquidation.control_number or liquidation.pk
	output_name = f'liquidation-{control_label}{extension}'
	return _render_fund_request_template_binary_from_template(template_record, placeholders, line_items, output_name)


def _build_liquidation_pdf_payload(liquidation, allow_structured_preview_fallback=False):
	template_record = liquidation.template
	template_extension = _fund_request_template_extension(template_record)

	base_payload = None
	if template_record and getattr(template_record, 'file', None):
		if template_extension == '.pdf':
			with template_record.file.open('rb') as template_file:
				base_payload = {
					'content': template_file.read(),
					'filename': f'liquidation-{liquidation.control_number or liquidation.pk}.pdf',
				}
				if base_payload:
					attachments_pdf = _build_fund_request_attachments_pdf_bytes(liquidation.attachments.all())
					merged_pdf = _merge_pdf_parts([base_payload['content'], attachments_pdf]) or base_payload['content']
					return {
						'content': merged_pdf,
						'filename': base_payload['filename'],
					}

		rendered_template = _render_liquidation_template_binary(liquidation)
		if rendered_template:
			pdf_bytes = _convert_office_bytes_to_pdf(
				rendered_template['content'],
				rendered_template['filename'],
				allow_structured_preview_fallback=allow_structured_preview_fallback,
			)
			if pdf_bytes:
				base_payload = {
					'content': pdf_bytes,
					'filename': f'{Path(rendered_template["filename"]).stem}.pdf',
				}
				attachments_pdf = _build_fund_request_attachments_pdf_bytes(liquidation.attachments.all())
				merged_pdf = _merge_pdf_parts([base_payload['content'], attachments_pdf]) or base_payload['content']
				return {
					'content': merged_pdf,
					'filename': base_payload['filename'],
				}

		if template_extension in {'.doc', '.xls'}:
			with template_record.file.open('rb') as template_file:
				pdf_bytes = _convert_office_bytes_to_pdf(
					template_file.read(),
					Path(template_record.file.name).name,
					allow_structured_preview_fallback=allow_structured_preview_fallback,
				)
			if pdf_bytes:
				base_payload = {
					'content': pdf_bytes,
					'filename': f'{Path(template_record.file.name).stem}.pdf',
				}
				attachments_pdf = _build_fund_request_attachments_pdf_bytes(liquidation.attachments.all())
				merged_pdf = _merge_pdf_parts([base_payload['content'], attachments_pdf]) or base_payload['content']
				return {
					'content': merged_pdf,
					'filename': base_payload['filename'],
				}

	content = render_to_string(
		'core/liquidation_document_pdf.html',
		{
			'liquidation': liquidation,
			'line_items': liquidation.items.all(),
			'template_record': liquidation.template,
			'template_extension': template_extension,
		},
	)
	pdf_bytes = _render_html_bytes_to_pdf(content.encode('utf-8'), f'liquidation-{liquidation.control_number or liquidation.pk}.html')
	if not pdf_bytes:
		summary_lines = [
			f'Name: {liquidation.name or "-"}',
			f'Date: {_format_fund_request_date(liquidation.liquidation_date) or "-"}',
			f'Branch: {liquidation.branch or "-"}',
			f'Position: {liquidation.position or "-"}',
			f'Total: PHP {_format_fund_request_amount(liquidation.total_amount)}',
			f'Amount Requested: PHP {_format_fund_request_amount(liquidation.amount_requested)}',
			f'{liquidation.get_returned_or_over_type_display() if hasattr(liquidation, "get_returned_or_over_type_display") else "Amount Returned/Over"}: PHP {_format_fund_request_amount(liquidation.amount_returned_or_over)}',
			f'Requested By: {liquidation.requested_by_name or "-"}',
			'',
			'Line Items:',
		]
		for index, line_item in enumerate(liquidation.items.all(), start=1):
			line_date = _format_fund_request_item_date(line_item.entry_date) or '-'
			summary_lines.append(
				f'{index}. {line_date} | {line_item.fund_form_no or "-"} | {line_item.description} | PHP {_format_fund_request_amount(line_item.amount)}'
			)
		if not liquidation.items.exists():
			summary_lines.append('No line items recorded.')
		pdf_bytes = _build_notice_pdf_bytes('Liquidation Summary', summary_lines)
		if not pdf_bytes:
			return None
	attachments_pdf = _build_fund_request_attachments_pdf_bytes(liquidation.attachments.all())
	merged_pdf = _merge_pdf_parts([pdf_bytes, attachments_pdf]) or pdf_bytes
	return {
		'content': merged_pdf,
		'filename': f'liquidation-{liquidation.control_number or liquidation.pk}.pdf',
	}


def _client_deletion_approvers_queryset():
	return (
		User.objects.filter(is_active=True)
		.filter(
			Q(is_superuser=True)
			| Q(user_permissions__content_type__app_label='core', user_permissions__codename='approve_clientdeletionrequest')
			| Q(groups__permissions__content_type__app_label='core', groups__permissions__codename='approve_clientdeletionrequest')
		)
		.distinct()
	)


def _notify_client_deletion_approvers(client_request):
	approval_link = f"{reverse('clients_list')}#clientDeletionApprovals"
	requester_name = '-'
	if client_request.requested_by:
		requester_name = client_request.requested_by.get_full_name() or client_request.requested_by.username

	for approver in _client_deletion_approvers_queryset():
		if client_request.requested_by_id and approver.id == client_request.requested_by_id:
			continue
		create_notification(
			approver,
			title='Client deletion approval needed',
			message=f'Deletion request for "{client_request.client_name_snapshot}" by {requester_name}.',
			link_url=approval_link,
		)


def _submit_client_deletion_request(client, requested_by, reason=''):
	reason_text = (reason or '').strip()
	existing_pending = ClientDeletionRequest.objects.filter(client=client, status='pending').first()
	if existing_pending:
		return 'pending', existing_pending

	rejected_request = (
		ClientDeletionRequest.objects
		.filter(client=client, status='rejected')
		.order_by('-requested_at')
		.first()
	)
	if rejected_request:
		rejected_request.status = 'pending'
		rejected_request.reason = reason_text
		rejected_request.requested_by = requested_by
		rejected_request.requested_at = timezone.now()
		rejected_request.resubmission_count = int(rejected_request.resubmission_count or 0) + 1
		rejected_request.reviewed_by = None
		rejected_request.reviewed_at = None
		rejected_request.review_notes = ''
		rejected_request.save(
			update_fields=[
				'status',
				'reason',
				'requested_by',
				'requested_at',
				'resubmission_count',
				'reviewed_by',
				'reviewed_at',
				'review_notes',
			]
		)
		_notify_client_deletion_approvers(rejected_request)
		return 'reopened', rejected_request

	deletion_request = ClientDeletionRequest.objects.create(
		client=client,
		client_name_snapshot=client.full_name,
		reason=reason_text,
		requested_by=requested_by,
	)
	_notify_client_deletion_approvers(deletion_request)
	return 'created', deletion_request


@login_required
def users_list(request):
	restricted_response = _require_permission(request, 'auth.view_user')
	if restricted_response:
		return restricted_response

	user_query = (request.GET.get('user_q') or '').strip()
	suspicious_query = (request.GET.get('suspicious_q') or '').strip()

	users = User.objects.prefetch_related('groups', 'user_permissions', 'groups__permissions').order_by('id')
	if user_query:
		users = users.filter(
			Q(username__icontains=user_query)
			| Q(email__icontains=user_query)
			| Q(groups__name__icontains=user_query)
		).distinct()

	suspicious_events = LoginEvent.objects.filter(
		Q(reason='locked_out') | Q(reason='invalid_credentials')
	).order_by('-created_at')
	if suspicious_query:
		suspicious_events = suspicious_events.filter(
			Q(username_attempt__icontains=suspicious_query)
			| Q(ip_address__icontains=suspicious_query)
			| Q(reason__icontains=suspicious_query)
		)

	users_page = Paginator(users, 10).get_page(request.GET.get('user_page'))
	suspicious_page = Paginator(suspicious_events, 10).get_page(request.GET.get('suspicious_page'))
	page_users = list(users_page.object_list)
	page_user_ids = [user.id for user in page_users]
	profiles_by_user_id = {
		profile.user_id: profile
		for profile in UserProfile.objects.filter(user_id__in=page_user_ids)
	}
	login_events_by_user_id = {user_id: [] for user_id in page_user_ids}
	for event in LoginEvent.objects.filter(user_id__in=page_user_ids).order_by('-created_at'):
		login_events_by_user_id.setdefault(event.user_id, []).append(event)

	user_rows = []
	user_profile_map = {}
	for managed_user in page_users:
		profile = profiles_by_user_id.get(managed_user.id)
		group_names = [group.name for group in managed_user.groups.all()]
		direct_permission_names = sorted(
			{
				format_permission_summary(permission)
				for permission in managed_user.user_permissions.select_related('content_type').all()
			}
		)
		group_permission_names = sorted(
			{
				format_permission_summary(permission)
				for group in managed_user.groups.all()
				for permission in group.permissions.select_related('content_type').all()
			}
		)
		all_events = login_events_by_user_id.get(managed_user.id, [])
		total_events = len(all_events)
		success_events = sum(1 for event in all_events if event.successful)
		failed_events = total_events - success_events
		recent_activity = [
			{
				'time': event.created_at.strftime('%Y-%m-%d %H:%M'),
				'status': 'Success' if event.successful else 'Failed',
				'reason': event.reason.replace('_', ' ').title(),
				'ip_address': event.ip_address or '-',
			}
			for event in login_events_by_user_id.get(managed_user.id, [])
		]
		avatar_seed = (managed_user.get_full_name() or managed_user.username or 'U').strip()
		avatar_parts = [part[0] for part in avatar_seed.split()[:2] if part]
		avatar_initials = ''.join(avatar_parts).upper() or managed_user.username[:2].upper()
		last_successful_login = (
			LoginEvent.objects.filter(user=managed_user, successful=True).order_by('-created_at').values_list('created_at', flat=True).first()
		)
		user_rows.append(
			{
				'user': managed_user,
				'groups': group_names,
				'branch': profile.branch if profile and profile.branch else '',
				'avatar_url': profile.avatar.url if profile and profile.avatar else '',
				'email_verified': profile.email_verified if profile else False,
				'last_login_ip': profile.last_login_ip if profile else None,
				'last_login_user_agent': profile.last_login_user_agent if profile else '',
				'date_joined': managed_user.date_joined,
				'last_login': managed_user.last_login,
			}
		)
		user_profile_map[str(managed_user.id)] = {
			'username': managed_user.username,
			'full_name': managed_user.get_full_name() or '-',
			'email': managed_user.email or '-',
			'roles': ', '.join(group_names) if group_names else 'No role',
			'branch': profile.branch if profile and profile.branch else 'Not assigned',
			'avatar_url': profile.avatar.url if profile and profile.avatar else '',
			'active_label': 'Active' if managed_user.is_active else 'Inactive',
			'staff_label': 'Yes' if managed_user.is_staff else 'No',
			'email_verified_label': 'Verified' if (profile.email_verified if profile else False) else 'Not verified',
			'last_login': managed_user.last_login.strftime('%Y-%m-%d %H:%M') if managed_user.last_login else '-',
			'joined': managed_user.date_joined.strftime('%Y-%m-%d %H:%M') if managed_user.date_joined else '-',
			'last_login_ip': profile.last_login_ip if profile and profile.last_login_ip else '-',
			'last_login_user_agent': profile.last_login_user_agent if profile and profile.last_login_user_agent else '-',
			'avatar_initials': avatar_initials,
			'account_stats': {
				'total_events': total_events,
				'success_events': success_events,
				'failed_events': failed_events,
				'last_successful_login': last_successful_login.strftime('%Y-%m-%d %H:%M') if last_successful_login else '-',
			},
			'recent_activity': recent_activity,
			'direct_permissions': direct_permission_names if request.user.is_superuser else [],
			'group_permissions': group_permission_names if request.user.is_superuser else [],
		}

	def _qs(**kwargs):
		params = {
			'user_q': user_query,
			'suspicious_q': suspicious_query,
			'user_page': users_page.number,
			'suspicious_page': suspicious_page.number,
		}
		params.update(kwargs)
		return urlencode({k: v for k, v in params.items() if str(v).strip()})

	context = {
		'users_page': users_page,
		'user_rows': user_rows,
		'user_profile_map': user_profile_map,
		'available_roles': Group.objects.order_by('name'),
		'user_q': user_query,
		'suspicious_page': suspicious_page,
		'suspicious_q': suspicious_query,
		'users_prev_qs': _qs(user_page=users_page.previous_page_number()) if users_page.has_previous() else '',
		'users_next_qs': _qs(user_page=users_page.next_page_number()) if users_page.has_next() else '',
		'suspicious_prev_qs': _qs(suspicious_page=suspicious_page.previous_page_number()) if suspicious_page.has_previous() else '',
		'suspicious_next_qs': _qs(suspicious_page=suspicious_page.next_page_number()) if suspicious_page.has_next() else '',
		'total_users': User.objects.count(),
		'active_users': User.objects.filter(is_active=True).count(),
		'staff_users': User.objects.filter(is_staff=True).count(),
		'suspicious_events_24h': LoginEvent.objects.filter(
			Q(reason='locked_out') | Q(reason='invalid_credentials'),
			created_at__gte=timezone.now() - timedelta(hours=24),
		).count(),
	}
	return render(request, 'core/users_list.html', context)


@login_required
def users_create(request):
	restricted_response = _require_permission(request, 'auth.add_user')
	if restricted_response:
		return restricted_response

	role_permissions_grouped_map = {}
	available_roles = Group.objects.prefetch_related('permissions').order_by('name')
	for role in available_roles:
		role_permissions_grouped_map[str(role.id)] = build_permission_preview_groups(role.permissions.all())

	if request.method == 'POST':
		form = StaffUserCreationForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request, 'User account created successfully.')
			return redirect('users_list')
	else:
		form = StaffUserCreationForm()

	return render(
		request,
		'core/users_form.html',
		{
			'form': form,
			'page_title': 'Create User',
			'submit_label': 'Create User',
			'role_permissions_grouped_map': role_permissions_grouped_map,
		},
	)


@login_required
def users_update(request, user_id):
	restricted_response = _require_permission(request, 'auth.change_user')
	if restricted_response:
		return restricted_response

	role_permissions_grouped_map = {}
	available_roles = Group.objects.prefetch_related('permissions').order_by('name')
	for role in available_roles:
		role_permissions_grouped_map[str(role.id)] = build_permission_preview_groups(role.permissions.all())

	managed_user = get_object_or_404(User, pk=user_id)

	if request.method == 'POST':
		form = StaffUserUpdateForm(request.POST, instance=managed_user)
		if form.is_valid():
			form.save()
			messages.success(request, 'User account updated successfully.')
			return redirect('users_list')
	else:
		form = StaffUserUpdateForm(instance=managed_user)

	return render(
		request,
		'core/users_form.html',
		{
			'form': form,
			'page_title': f'Edit User: {managed_user.username}',
			'submit_label': 'Save Changes',
			'role_permissions_grouped_map': role_permissions_grouped_map,
		},
	)


@login_required
def users_delete(request, user_id):
	restricted_response = _require_permission(request, 'auth.delete_user')
	if restricted_response:
		return restricted_response

	managed_user = get_object_or_404(User, pk=user_id)
	if request.method == 'POST':
		managed_user.delete()
		messages.success(request, 'User account deleted successfully.')
		return redirect('users_list')

	return render(request, 'core/users_confirm_delete.html', {'managed_user': managed_user})


@login_required
@require_POST
def users_bulk_delete(request):
	restricted_response = _require_permission(request, 'auth.delete_user')
	if restricted_response:
		return restricted_response

	user_ids = request.POST.getlist('user_ids')
	if not user_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			user_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in user_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No user accounts selected.')
		return redirect('users_list')

	# Prevent accidental self-delete in bulk action.
	parsed_ids = [uid for uid in parsed_ids if uid != request.user.id]
	if not parsed_ids:
		messages.warning(request, 'You cannot delete your own active account in bulk action.')
		return redirect('users_list')

	users = User.objects.filter(pk__in=parsed_ids)
	count = users.count()
	users.delete()

	if count:
		messages.success(request, f'{count} user account(s) deleted successfully.')
	else:
		messages.warning(request, 'No matching users found.')

	return redirect('users_list')


@login_required
@require_POST
def users_bulk_update_status(request):
	restricted_response = _require_permission(request, 'auth.change_user')
	if restricted_response:
		return restricted_response

	status_action = (request.POST.get('status_action') or '').strip().lower()
	if status_action not in {'activate', 'deactivate'}:
		messages.error(request, 'Invalid user status action.')
		return redirect('users_list')

	user_ids = request.POST.getlist('user_ids')
	if not user_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			user_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in user_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No user accounts selected.')
		return redirect('users_list')

	if status_action == 'deactivate':
		parsed_ids = [uid for uid in parsed_ids if uid != request.user.id]
		if not parsed_ids:
			messages.warning(request, 'You cannot deactivate your own active account in bulk action.')
			return redirect('users_list')

	new_state = (status_action == 'activate')
	updated = User.objects.filter(pk__in=parsed_ids).update(is_active=new_state)

	verb = 'activated' if new_state else 'deactivated'
	if updated:
		messages.success(request, f'{updated} user account(s) {verb} successfully.')
	else:
		messages.warning(request, 'No matching users found.')

	return redirect('users_list')


@login_required
@require_POST
def users_bulk_update_role(request):
	restricted_response = _require_permission(request, 'auth.change_user')
	if restricted_response:
		return restricted_response

	role_action = (request.POST.get('role_action') or '').strip().lower()
	if role_action not in {'assign', 'remove', 'replace'}:
		messages.error(request, 'Invalid role action.')
		return redirect('users_list')

	role_id = (request.POST.get('role_id') or '').strip()
	if not role_id.isdigit():
		messages.error(request, 'Please select a valid role.')
		return redirect('users_list')

	role = get_object_or_404(Group, pk=int(role_id))

	user_ids = request.POST.getlist('user_ids')
	if not user_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			user_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in user_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No user accounts selected.')
		return redirect('users_list')

	if role_action in {'remove', 'replace'}:
		parsed_ids = [uid for uid in parsed_ids if uid != request.user.id]
		if not parsed_ids:
			messages.warning(request, 'You cannot bulk remove/replace roles on your own active account.')
			return redirect('users_list')

	users = list(User.objects.filter(pk__in=parsed_ids).prefetch_related('groups'))
	if not users:
		messages.warning(request, 'No matching users found.')
		return redirect('users_list')

	changed_count = 0
	for user in users:
		has_role = user.groups.filter(pk=role.pk).exists()
		if role_action == 'assign' and not has_role:
			user.groups.add(role)
			changed_count += 1
		elif role_action == 'remove' and has_role:
			user.groups.remove(role)
			changed_count += 1
		elif role_action == 'replace':
			current_role_ids = set(user.groups.values_list('id', flat=True))
			if current_role_ids != {role.id}:
				user.groups.set([role])
				changed_count += 1

	action_label_map = {
		'assign': 'assigned to',
		'remove': 'removed from',
		'replace': 'set as only role for',
	}
	action_label = action_label_map[role_action]
	if changed_count:
		messages.success(request, f'Role "{role.name}" {action_label} {changed_count} user account(s).')
	else:
		messages.info(request, f'No users changed. Selected users already have the role state you requested.')

	return redirect('users_list')


@login_required
def clients_list(request):
	restricted_response = _require_permission(request, 'core.view_client')
	if restricted_response:
		return restricted_response

	query = (request.GET.get('q') or '').strip()
	clients = _filter_clients_by_visibility(
		request,
		Client.objects.select_related('handled_by', 'handled_by__profile', 'created_by')
	).order_by('-created_at')
	if query:
		clients = clients.filter(
			Q(full_name__icontains=query)
			| Q(email__icontains=query)
			| Q(active_phone_number__icontains=query)
			| Q(status__icontains=query)
			| Q(lead_status__icontains=query)
			| Q(lead_disposition_reason__icontains=query)
			| Q(client_type__icontains=query)
			| Q(handled_by__username__icontains=query)
		)

	clients_stats_queryset = _filter_clients_by_visibility(request, Client.objects.all())

	clients_page = Paginator(clients, 20).get_page(request.GET.get('page'))
	page_clients = list(clients_page.object_list)
	client_ids = [client.id for client in page_clients]
	handled_by_ids = [client.handled_by_id for client in page_clients if client.handled_by_id]
	handler_profiles_map = {
		profile.user_id: profile
		for profile in UserProfile.objects.filter(user_id__in=handled_by_ids)
	}
	quotation_counts = {
		item['client_id']: item['total']
		for item in ClientQuotation.objects.filter(client_id__in=client_ids)
		.values('client_id')
		.annotate(total=Count('id'))
	}
	latest_versions = {
		item['client_id']: item['latest_version']
		for item in ClientQuotation.objects.filter(client_id__in=client_ids)
		.values('client_id')
		.annotate(latest_version=Max('version'))
	}

	can_approve_client_deletions = request.user.is_superuser or request.user.has_perm('core.approve_clientdeletionrequest')
	pending_client_deletion_requests = []
	if can_approve_client_deletions:
		pending_client_deletion_requests = list(
			ClientDeletionRequest.objects
			.filter(status='pending')
			.select_related('client', 'requested_by')
			.order_by('-requested_at')[:100]
		)

	context = {
		'clients_page': clients_page,
		'handler_profiles_map': handler_profiles_map,
		'quotation_counts': quotation_counts,
		'latest_versions': latest_versions,
		'client_status_choices': Client.STATUS_CHOICES,
		'query': query,
		'total_clients': clients_stats_queryset.count(),
		'new_clients': clients_stats_queryset.filter(client_type='new').count(),
		'old_clients': clients_stats_queryset.filter(client_type='old').count(),
		'inquiry_clients': clients_stats_queryset.filter(status='inquiry').count(),
		'intake_leads': clients_stats_queryset.filter(lead_status='intake').count(),
		'converted_leads': clients_stats_queryset.filter(lead_status='converted').count(),
		'lost_leads': clients_stats_queryset.filter(lead_status='lost').count(),
		'qualified_leads': clients_stats_queryset.filter(lead_status='qualified').count(),
		'not_qualified_leads': clients_stats_queryset.filter(lead_status='not_qualified').count(),
		'can_approve_client_deletions': can_approve_client_deletions,
		'pending_client_deletion_requests': pending_client_deletion_requests,
	}
	return render(request, 'core/clients_list.html', context)


def _get_fund_request_records_context_data(request):
	query = (request.GET.get('q') or '').strip()
	record_date_raw = (request.GET.get('record_date') or '').strip()
	record_date = parse_date(record_date_raw) if record_date_raw else None
	request_status_filter = (request.GET.get('request_status') or '').strip().lower()
	created_from = (request.GET.get('created_from') or '').strip()
	created_to = (request.GET.get('created_to') or '').strip()
	series_from = (request.GET.get('series_from') or '').strip()
	series_to = (request.GET.get('series_to') or '').strip()
	amount_min = (request.GET.get('amount_min') or '').strip()
	amount_max = (request.GET.get('amount_max') or '').strip()

	can_view_all_request_records = request.user.is_superuser or _can_approve_fund_requests(request.user)
	base_queryset = FundRequest.objects.select_related('created_by', 'created_by__profile', 'template', 'processed_by')
	visible_queryset = base_queryset if can_view_all_request_records else base_queryset.filter(created_by=request.user)

	def parse_local_datetime(value):
		if not value:
			return None
		datetime_value = parse_datetime(value)
		if not datetime_value:
			return None
		if timezone.is_naive(datetime_value):
			datetime_value = timezone.make_aware(datetime_value, timezone.get_current_timezone())
		return datetime_value

	created_from_datetime = parse_local_datetime(created_from)
	created_to_datetime = parse_local_datetime(created_to)
	valid_status_values = {status_value for status_value, _status_label in FundRequest.REQUEST_STATUS_CHOICES}
	status_label_map = {value: label for value, label in FundRequest.REQUEST_STATUS_CHOICES}

	filtered_queryset = visible_queryset
	if request_status_filter in valid_status_values:
		filtered_queryset = filtered_queryset.filter(request_status=request_status_filter)
	if record_date:
		filtered_queryset = filtered_queryset.filter(request_date=record_date)
	if created_from_datetime:
		filtered_queryset = filtered_queryset.filter(created_at__gte=created_from_datetime)
	if created_to_datetime:
		filtered_queryset = filtered_queryset.filter(created_at__lte=created_to_datetime)
	if query:
		filtered_queryset = filtered_queryset.filter(
			Q(serial_number__icontains=query)
			| Q(requester_name__icontains=query)
			| Q(department__icontains=query)
			| Q(branch__icontains=query)
		)
	if series_from:
		filtered_queryset = filtered_queryset.filter(serial_number__gte=series_from)
	if series_to:
		filtered_queryset = filtered_queryset.filter(serial_number__lte=series_to)
	if amount_min:
		try:
			filtered_queryset = filtered_queryset.filter(total_amount__gte=Decimal(amount_min))
		except (InvalidOperation, TypeError, ValueError):
			pass
	if amount_max:
		try:
			filtered_queryset = filtered_queryset.filter(total_amount__lte=Decimal(amount_max))
		except (InvalidOperation, TypeError, ValueError):
			pass

	filter_parts = []
	if query:
		filter_parts.append(f'Search: {query}')
	if request_status_filter in status_label_map:
		filter_parts.append(f'Status: {status_label_map[request_status_filter]}')
	if record_date:
		filter_parts.append(f'Request Date: {record_date.isoformat()}')
	if created_from_datetime:
		filter_parts.append(f'Created From: {timezone.localtime(created_from_datetime).strftime("%Y-%m-%d %H:%M")}')
	if created_to_datetime:
		filter_parts.append(f'Created To: {timezone.localtime(created_to_datetime).strftime("%Y-%m-%d %H:%M")}')
	if series_from:
		filter_parts.append(f'Series From: {series_from}')
	if series_to:
		filter_parts.append(f'Series To: {series_to}')
	if amount_min:
		filter_parts.append(f'Min Amount: {amount_min}')
	if amount_max:
		filter_parts.append(f'Max Amount: {amount_max}')

	filter_state = {
		'query': query,
		'request_status': request_status_filter if request_status_filter in valid_status_values else '',
		'record_date': record_date.isoformat() if record_date else '',
		'created_from': created_from,
		'created_to': created_to,
		'series_from': series_from,
		'series_to': series_to,
		'amount_min': amount_min,
		'amount_max': amount_max,
	}
	return {
		'can_view_all_request_records': can_view_all_request_records,
		'visible_queryset': visible_queryset,
		'filtered_queryset': filtered_queryset,
		'filter_state': filter_state,
		'filter_summary': ' | '.join(filter_parts) if filter_parts else 'No filters applied.',
		'status_label_map': status_label_map,
	}


@login_required
def fund_requests_list(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	query = (request.GET.get('q') or '').strip()
	date_from_raw = (request.GET.get('date_from') or '').strip()
	date_to_raw = (request.GET.get('date_to') or '').strip()
	date_from = parse_date(date_from_raw) if date_from_raw else None
	date_to = parse_date(date_to_raw) if date_to_raw else None
	record_date_raw = (request.GET.get('record_date') or '').strip()
	record_date = parse_date(record_date_raw) if record_date_raw else None
	request_status_filter = (request.GET.get('request_status') or '').strip().lower()
	created_from = (request.GET.get('created_from') or '').strip()
	created_to = (request.GET.get('created_to') or '').strip()
	series_from = (request.GET.get('series_from') or '').strip()
	series_to = (request.GET.get('series_to') or '').strip()
	amount_min = (request.GET.get('amount_min') or '').strip()
	amount_max = (request.GET.get('amount_max') or '').strip()
	selected_template_id = ''
	can_add_fund_requests = request.user.is_superuser or request.user.has_perm('core.add_fundrequest')
	can_delete_fund_requests = request.user.is_superuser or request.user.has_perm('core.delete_fundrequest')
	can_approve_fund_requests = _can_approve_fund_requests(request.user)
	can_cancel_other_fund_requests = _can_cancel_other_fund_requests(request.user)
	can_view_all_request_records = request.user.is_superuser or can_approve_fund_requests
	can_manage_templates = _can_manage_fund_request_templates(request.user)
	auto_approve_rules = list(FundRequestAutoApproveRule.objects.select_related('created_by').order_by('-is_active', '-updated_at', '-created_at'))
	active_template = FundRequestTemplate.objects.filter(is_active=True).order_by('-updated_at', '-created_at').first()
	all_templates = list(
		FundRequestTemplate.objects.select_related('uploaded_by', 'uploaded_by__profile').order_by('-is_active', '-updated_at', '-created_at')
	)
	guide_template = active_template or (all_templates[0] if all_templates else None)
	all_fund_requests_queryset = FundRequest.objects.select_related('created_by', 'created_by__profile', 'template', 'processed_by').prefetch_related('items', 'attachments')
	visible_fund_requests_queryset = all_fund_requests_queryset
	if not can_view_all_request_records:
		visible_fund_requests_queryset = visible_fund_requests_queryset.filter(created_by=request.user)

	def parse_local_datetime(value):
		if not value:
			return None
		datetime_value = parse_datetime(value)
		if not datetime_value:
			return None
		if timezone.is_naive(datetime_value):
			datetime_value = timezone.make_aware(datetime_value, timezone.get_current_timezone())
		return datetime_value

	created_from_datetime = parse_local_datetime(created_from)
	created_to_datetime = parse_local_datetime(created_to)
	valid_status_values = {status_value for status_value, _status_label in FundRequest.REQUEST_STATUS_CHOICES}

	if request.method == 'POST':
		action_type = (request.POST.get('action_type') or '').strip()
		template_action = (request.POST.get('template_action') or '').strip()
		template_action_id = ''
		if template_action:
			action_name, _, action_id = template_action.partition(':')
			template_action_id = action_id.strip()
			if action_name == 'set_default':
				action_type = 'set_default_template'
			elif action_name == 'delete':
				action_type = 'delete_template'
		if not action_type:
			action_type = 'create_request'
		if action_type == 'upload_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to upload fund request templates.')

			template_form = FundRequestTemplateForm(request.POST, request.FILES)
			request_form = FundRequestForm(initial={'request_date': timezone.localdate()}, user=request.user)
			if template_form.is_valid():
				template_record = template_form.save(commit=False)
				template_record.uploaded_by = request.user
				template_record.save()
				messages.success(request, f'Fund request template "{template_record.name}" uploaded successfully.')
				return redirect('fund_requests_list')
		elif action_type == 'delete_request':
			if not can_delete_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to remove fund requests.')

			request_id = request.POST.get('request_id')
			fund_request = get_object_or_404(visible_fund_requests_queryset, pk=request_id)
			record_label = fund_request.serial_number or fund_request.requester_name or f'#{fund_request.pk}'
			fund_request.delete()
			messages.success(request, f'Fund request {record_label} removed successfully.')
			return redirect('fund_requests_list')
		elif action_type == 'bulk_delete_requests':
			if not can_delete_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to remove fund requests.')

			selected_ids = [
				int(value)
				for value in request.POST.getlist('selected_request_ids')
				if str(value).isdigit()
			]
			if not selected_ids:
				messages.warning(request, 'Select at least one fund request to remove.')
				return redirect('fund_requests_list')

			fund_requests_to_delete = list(visible_fund_requests_queryset.filter(pk__in=selected_ids, request_status='approved'))
			deleted_count = len(fund_requests_to_delete)
			visible_fund_requests_queryset.filter(pk__in=selected_ids, request_status='approved').delete()
			if deleted_count == 0:
				messages.warning(request, 'No approved fund requests matched the selected records.')
				return redirect('fund_requests_list')
			messages.success(request, f'{deleted_count} fund request(s) removed successfully.')
			return redirect('fund_requests_list')
		elif action_type == 'bulk_delete_templates':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to remove fund request templates.')

			selected_template_ids = [
				int(value)
				for value in request.POST.getlist('selected_template_ids')
				if str(value).isdigit()
			]
			if not selected_template_ids:
				messages.warning(request, 'Select at least one uploaded template to remove.')
				return redirect('fund_requests_list')

			template_count = FundRequestTemplate.objects.filter(pk__in=selected_template_ids).count()
			FundRequestTemplate.objects.filter(pk__in=selected_template_ids).delete()
			_ensure_active_fund_request_template()
			messages.success(request, f'{template_count} uploaded template(s) removed successfully.')
			return redirect('fund_requests_list')
		elif action_type == 'set_default_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to update fund request templates.')

			template_id = template_action_id or (request.POST.get('template_id') or '').strip()
			if not template_id.isdigit():
				messages.warning(request, 'Select a valid template to set as default.')
				return redirect('fund_requests_list')

			template_record = get_object_or_404(FundRequestTemplate, pk=int(template_id))
			if template_record.is_active:
				messages.info(request, f'"{template_record.name}" is already the default template.')
				return redirect('fund_requests_list')

			template_record.is_active = True
			template_record.save(update_fields=['is_active'])
			messages.success(request, f'"{template_record.name}" is now the default template.')
			return redirect('fund_requests_list')
		elif action_type == 'delete_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to remove fund request templates.')

			template_id = template_action_id or (request.POST.get('template_id') or '').strip()
			if not template_id.isdigit():
				messages.warning(request, 'Select a valid template to remove.')
				return redirect('fund_requests_list')

			template_record = get_object_or_404(FundRequestTemplate, pk=int(template_id))
			template_name = template_record.name
			template_record.delete()
			_ensure_active_fund_request_template()
			messages.success(request, f'Template "{template_name}" removed successfully.')
			return redirect('fund_requests_list')
		elif action_type == 'approve_request':
			if not can_approve_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to approve fund requests.')

			request_id = request.POST.get('request_id')
			reason = (request.POST.get('reason') or '').strip()

			fund_request = get_object_or_404(FundRequest.objects.select_related('created_by'), pk=request_id)
			if fund_request.request_status != 'pending':
				messages.info(request, 'This fund request has already been reviewed.')
				return redirect('fund_requests_list')

			with transaction.atomic():
				fund_request = FundRequest.objects.select_for_update().select_related('created_by').get(pk=request_id)
				if fund_request.request_status != 'pending':
					messages.info(request, 'This fund request has already been reviewed.')
					return redirect('fund_requests_list')
				fund_request.mark_approved(processed_by=request.user, reason=reason)
			_notify_fund_request_requester(fund_request)
			messages.success(request, f'Fund request approved with serial number {fund_request.serial_number}.')
			return redirect('fund_requests_list')
		elif action_type == 'reject_request':
			if not can_approve_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to reject fund requests.')

			request_id = request.POST.get('request_id')
			reason = (request.POST.get('reason') or '').strip()

			fund_request = get_object_or_404(FundRequest.objects.select_related('created_by'), pk=request_id)
			if fund_request.request_status != 'pending':
				messages.info(request, 'This fund request has already been reviewed.')
				return redirect('fund_requests_list')

			with transaction.atomic():
				fund_request = FundRequest.objects.select_for_update().select_related('created_by').get(pk=request_id)
				if fund_request.request_status != 'pending':
					messages.info(request, 'This fund request has already been reviewed.')
					return redirect('fund_requests_list')
				fund_request.mark_rejected(processed_by=request.user, reason=reason)
			_notify_fund_request_requester(fund_request)
			messages.info(request, 'Fund request rejected.')
			return redirect('fund_requests_list')
		elif action_type == 'cancel_request':
			request_id = request.POST.get('request_id')
			reason = (request.POST.get('reason') or '').strip()

			fund_request = get_object_or_404(FundRequest.objects.select_related('created_by'), pk=request_id)
			can_cancel_request = (
				fund_request.created_by_id == request.user.id
				or can_cancel_other_fund_requests
			)
			if not can_cancel_request:
				return _permission_denied_response(request, 'You do not have permission to cancel this fund request.')
			if fund_request.request_status != 'pending':
				messages.info(request, 'Only pending fund requests can be cancelled.')
				return redirect('fund_requests_list')

			with transaction.atomic():
				fund_request = FundRequest.objects.select_for_update().select_related('created_by').get(pk=request_id)
				can_cancel_request = (
					fund_request.created_by_id == request.user.id
					or can_cancel_other_fund_requests
				)
				if not can_cancel_request:
					return _permission_denied_response(request, 'You do not have permission to cancel this fund request.')
				if fund_request.request_status != 'pending':
					messages.info(request, 'Only pending fund requests can be cancelled.')
					return redirect('fund_requests_list')
				fund_request.mark_cancelled(processed_by=request.user, reason=reason)

			if fund_request.created_by_id and fund_request.created_by_id != request.user.id:
				_notify_fund_request_requester(fund_request)
			if fund_request.created_by_id == request.user.id:
				messages.success(request, 'Your fund request has been cancelled.')
			else:
				request_label = fund_request.requester_name or f'#{fund_request.pk}'
				messages.success(request, f'Fund request for {request_label} has been cancelled.')
			return redirect('fund_requests_list')
		elif action_type == 'bulk_decide_pending_requests':
			if not can_approve_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to review pending fund requests.')

			decision = (request.POST.get('decision') or '').strip().lower()
			if decision not in {'approve', 'reject'}:
				messages.error(request, 'Invalid pending request bulk action.')
				return redirect('fund_requests_list')

			reason = (request.POST.get('reason') or '').strip()

			request_ids = request.POST.getlist('pending_request_ids')
			if not request_ids:
				request_ids = request.POST.getlist('request_ids')
			if not request_ids:
				request_ids = request.POST.getlist('selected_request_ids')
			if not request_ids:
				raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
				if raw_selected_ids:
					request_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

			parsed_ids = []
			for raw_id in request_ids:
				raw_text = str(raw_id).strip()
				if raw_text.isdigit():
					parsed_ids.append(int(raw_text))
			parsed_ids = sorted(set(parsed_ids))

			if not parsed_ids:
				messages.warning(request, 'No pending fund requests selected.')
				return redirect('fund_requests_list')

			pending_queryset = FundRequest.objects.select_related('created_by').filter(
				pk__in=parsed_ids,
				request_status='pending',
			)
			if not can_view_all_request_records:
				pending_queryset = pending_queryset.filter(created_by=request.user)

			processed_requests = []
			with transaction.atomic():
				for fund_request in pending_queryset.select_for_update():
					if decision == 'approve':
						fund_request.mark_approved(processed_by=request.user, reason=reason)
					else:
						fund_request.mark_rejected(processed_by=request.user, reason=reason)
					processed_requests.append(fund_request)

			processed_count = len(processed_requests)
			for processed_request in processed_requests:
				_notify_fund_request_requester(processed_request)

			if processed_count:
				if decision == 'approve':
					messages.success(request, f'{processed_count} pending fund request(s) approved successfully.')
				else:
					messages.info(request, f'{processed_count} pending fund request(s) rejected.')
			else:
				messages.warning(request, 'No pending fund requests matched the selected records.')

			skipped_count = max(0, len(parsed_ids) - processed_count)
			if skipped_count:
				messages.warning(request, f'{skipped_count} selected request(s) were skipped because they were already reviewed or unavailable.')
			return redirect('fund_requests_list')
		elif action_type == 'save_auto_approve_rule':
			if not can_approve_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to auto approve pending fund requests.')

			rule_name = (request.POST.get('auto_rule_name') or '').strip()
			if not rule_name:
				messages.warning(request, 'Rule name is required.')
				return redirect('fund_requests_list')

			requester_keyword = (request.POST.get('auto_requester_keyword') or '').strip()
			department_keyword = (request.POST.get('auto_department_keyword') or '').strip()
			branch_keyword = (request.POST.get('auto_branch_keyword') or '').strip()
			request_date_from = parse_date((request.POST.get('auto_request_date_from') or '').strip() or '')
			request_date_to = parse_date((request.POST.get('auto_request_date_to') or '').strip() or '')
			reason = (request.POST.get('auto_reason') or '').strip()
			require_attachments = (request.POST.get('auto_require_attachments') or '').strip() == '1'

			min_amount = _parse_optional_amount(request.POST.get('auto_min_amount'))
			max_amount = _parse_optional_amount(request.POST.get('auto_max_amount'))
			if min_amount is not None and max_amount is not None and min_amount > max_amount:
				messages.warning(request, 'Min amount cannot be greater than max amount.')
				return redirect('fund_requests_list')

			FundRequestAutoApproveRule.objects.create(
				name=rule_name[:120],
				requester_keyword=requester_keyword,
				department_keyword=department_keyword,
				branch_keyword=branch_keyword,
				request_date_from=request_date_from,
				request_date_to=request_date_to,
				min_amount=min_amount,
				max_amount=max_amount,
				require_attachments=require_attachments,
				reason=reason,
				is_active=True,
				created_by=request.user,
			)
			messages.success(request, f'Auto-approve rule "{rule_name}" saved and activated.')
			return redirect('fund_requests_list')
		elif action_type == 'toggle_auto_approve_rule':
			if not can_approve_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to update auto-approve rules.')

			rule_id = (request.POST.get('rule_id') or '').strip()
			if not rule_id.isdigit():
				messages.warning(request, 'Select a valid auto-approve rule.')
				return redirect('fund_requests_list')
			rule = get_object_or_404(FundRequestAutoApproveRule, pk=int(rule_id))
			rule.is_active = not rule.is_active
			rule.save(update_fields=['is_active', 'updated_at'])
			state_label = 'activated' if rule.is_active else 'deactivated'
			messages.success(request, f'Auto-approve rule "{rule.name}" {state_label}.')
			return redirect('fund_requests_list')
		else:
			if not can_add_fund_requests:
				return _permission_denied_response(request, 'You do not have permission to create fund requests.')

			request_form = FundRequestForm(request.POST, request.FILES, user=request.user)
			template_form = FundRequestTemplateForm()
			selected_template_id = (request.POST.get('selected_template_id') or '').strip()
			is_request_form_valid = request_form.is_valid()
			selected_template = None
			if selected_template_id.isdigit():
				selected_template = FundRequestTemplate.objects.filter(pk=int(selected_template_id)).first()

			if not selected_template:
				request_form.add_error(None, 'Select an uploaded template before saving the fund request.')

			if is_request_form_valid and selected_template:
				fund_request = request_form.save(commit=False)
				fund_request.created_by = request.user
				fund_request.template = selected_template
				fund_request.request_status = 'pending'
				fund_request.save()
				request_form.save_line_items(fund_request)
				request_form.save_attachments(fund_request, uploaded_by=request.user)
				matching_auto_rule = _get_matching_auto_approve_rule_for_fund_request(fund_request)
				if matching_auto_rule:
					approval_reason = (matching_auto_rule.reason or '').strip() or f'Auto-approved by rule: {matching_auto_rule.name}'
					auto_processor = matching_auto_rule.created_by if matching_auto_rule.created_by_id else None
					fund_request.mark_approved(processed_by=auto_processor, reason=approval_reason)
					messages.success(request, f'Fund request auto-approved by rule "{matching_auto_rule.name}".')
				else:
					_notify_fund_request_approvers(fund_request)
					messages.success(request, 'Fund request submitted for admin approval.')
				return redirect('fund_requests_list')
	else:
		request_form = FundRequestForm(initial={'request_date': timezone.localdate()}, user=request.user)
		template_form = FundRequestTemplateForm()

	pending_requests_queryset = visible_fund_requests_queryset.filter(request_status='pending')

	rejected_request_modal = None
	rejected_request_id = (request.GET.get('rejected_request') or '').strip()
	if rejected_request_id.isdigit():
		rejected_request_modal = visible_fund_requests_queryset.filter(pk=int(rejected_request_id), request_status='rejected').first()

	fund_requests_queryset = visible_fund_requests_queryset.filter(request_status='approved')
	if query:
		fund_requests_queryset = fund_requests_queryset.filter(
			Q(serial_number__icontains=query)
			| Q(requester_name__icontains=query)
			| Q(department__icontains=query)
			| Q(branch__icontains=query)
		)
	if date_from:
		fund_requests_queryset = fund_requests_queryset.filter(request_date__gte=date_from)
	if date_to:
		fund_requests_queryset = fund_requests_queryset.filter(request_date__lte=date_to)
	if series_from:
		fund_requests_queryset = fund_requests_queryset.filter(serial_number__gte=series_from)
	if series_to:
		fund_requests_queryset = fund_requests_queryset.filter(serial_number__lte=series_to)
	if amount_min:
		try:
			fund_requests_queryset = fund_requests_queryset.filter(total_amount__gte=Decimal(amount_min))
		except (InvalidOperation, TypeError, ValueError):
			pass
	if amount_max:
		try:
			fund_requests_queryset = fund_requests_queryset.filter(total_amount__lte=Decimal(amount_max))
		except (InvalidOperation, TypeError, ValueError):
			pass

	pending_requests_page = Paginator(
		pending_requests_queryset.order_by('-created_at'),
		10,
	).get_page(request.GET.get('pending_page'))
	fund_requests_page = Paginator(fund_requests_queryset.order_by('-created_at', '-id'), 10).get_page(request.GET.get('page'))
	page_requests = list(fund_requests_page.object_list)
	pending_page_requests = list(pending_requests_page.object_list)
	for fund_request in page_requests:
		fund_request.calculated_total_amount = sum(
			((line_item.amount or Decimal('0.00')) for line_item in fund_request.items.all()),
			Decimal('0.00'),
		)
	created_by_ids = {
		fund_request.created_by_id
		for fund_request in [*page_requests, *pending_page_requests]
		if fund_request.created_by_id
	}
	creator_profiles_map = {
		profile.user_id: profile
		for profile in UserProfile.objects.filter(user_id__in=created_by_ids)
	}
	status_label_map = {value: label for value, label in FundRequest.REQUEST_STATUS_CHOICES}
	records_filter_parts = []
	if query:
		records_filter_parts.append(f'Search: {query}')
	if date_from:
		records_filter_parts.append(f'Date From: {date_from.isoformat()}')
	if date_to:
		records_filter_parts.append(f'Date To: {date_to.isoformat()}')
	if request_status_filter in status_label_map:
		records_filter_parts.append(f'Status: {status_label_map[request_status_filter]}')
	if record_date:
		records_filter_parts.append(f'Request Date: {record_date.isoformat()}')
	if created_from_datetime:
		records_filter_parts.append(f'Created From: {timezone.localtime(created_from_datetime).strftime("%Y-%m-%d %H:%M")}')
	if created_to_datetime:
		records_filter_parts.append(f'Created To: {timezone.localtime(created_to_datetime).strftime("%Y-%m-%d %H:%M")}')
	if series_from:
		records_filter_parts.append(f'Series From: {series_from}')
	if series_to:
		records_filter_parts.append(f'Series To: {series_to}')
	if amount_min:
		records_filter_parts.append(f'Min Amount: {amount_min}')
	if amount_max:
		records_filter_parts.append(f'Max Amount: {amount_max}')
	records_filter_summary = ' | '.join(records_filter_parts) if records_filter_parts else 'No filters applied.'
	total_visible_approved_requests = visible_fund_requests_queryset.filter(request_status='approved').count()
	total_visible_pending_requests = visible_fund_requests_queryset.filter(request_status='pending').count()

	context = {
		'pending_requests_page': pending_requests_page,
		'fund_requests_page': fund_requests_page,
		'creator_profiles_map': creator_profiles_map,
		'fund_request_form': request_form,
		'template_form': template_form,
		'quick_placeholder_guide': _build_fund_request_template_quick_placeholder_guide(),
		'all_templates': all_templates,
		'guide_template': guide_template,
		'guide_preview_url': reverse('fund_request_template_guide'),
		'default_selected_template_id': selected_template_id or (active_template.id if active_template else ''),
		'query': query,
		'date_from': date_from.isoformat() if date_from else '',
		'date_to': date_to.isoformat() if date_to else '',
		'record_date': record_date.isoformat() if record_date else '',
		'request_status': request_status_filter if request_status_filter in valid_status_values else '',
		'request_status_choices': FundRequest.REQUEST_STATUS_CHOICES,
		'created_from': created_from,
		'created_to': created_to,
		'series_from': series_from,
		'series_to': series_to,
		'amount_min': amount_min,
		'amount_max': amount_max,
		'active_template': active_template,
		'can_add_fund_requests': can_add_fund_requests,
		'can_delete_fund_requests': can_delete_fund_requests,
		'can_approve_fund_requests': can_approve_fund_requests,
		'can_cancel_other_fund_requests': can_cancel_other_fund_requests,
		'can_view_all_request_records': can_view_all_request_records,
		'can_manage_templates': can_manage_templates,
		'total_fund_requests': total_visible_approved_requests,
		'total_pending_fund_requests': total_visible_pending_requests,
		'records_filter_summary': records_filter_summary,
		'print_generated_at': timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S'),
		'rejected_request_modal': rejected_request_modal,
		'rejected_request_modal_total': rejected_request_modal.items.aggregate(total=Sum('amount')).get('total') if rejected_request_modal else None,
		'auto_approve_rules': auto_approve_rules,
	}
	return render(request, 'core/fund_requests_list.html', context)


@login_required
def fund_request_template_guide(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	template_record = (
		FundRequestTemplate.objects.select_related('uploaded_by', 'uploaded_by__profile')
		.filter(is_active=True)
		.order_by('-updated_at', '-created_at')
		.first()
	)
	if not template_record:
		template_record = (
			FundRequestTemplate.objects.select_related('uploaded_by', 'uploaded_by__profile')
			.order_by('-updated_at', '-created_at')
			.first()
		)

	return render(
		request,
		'core/fund_request_template_preview.html',
		_build_fund_request_template_preview_page_context(template_record, show_template_page_link=True),
	)


@login_required
def fund_request_records(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	records_context = _get_fund_request_records_context_data(request)
	records_queryset = records_context['filtered_queryset'].order_by('-created_at', '-id')
	records_page = Paginator(records_queryset, 30).get_page(request.GET.get('page'))
	context = {
		'records_page': records_page,
		'filter_state': records_context['filter_state'],
		'filter_summary': records_context['filter_summary'],
		'request_status_choices': FundRequest.REQUEST_STATUS_CHOICES,
		'status_label_map': records_context['status_label_map'],
		'can_view_all_request_records': records_context['can_view_all_request_records'],
		'generated_at': timezone.localtime(timezone.now()),
		'generated_by_label': request.user.get_full_name() or request.user.username,
		'auto_print': (request.GET.get('auto_print') or '').strip() == '1',
	}
	return render(request, 'core/fund_request_records.html', context)


@login_required
def fund_request_records_pdf(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	records_context = _get_fund_request_records_context_data(request)
	records_queryset = records_context['filtered_queryset'].order_by('-created_at', '-id')
	generated_at = timezone.localtime(timezone.now())
	generated_by_label = request.user.get_full_name() or request.user.username
	filename_stamp = generated_at.strftime('%Y%m%d_%H%M%S')

	scope_label = 'All requests' if records_context['can_view_all_request_records'] else 'My requests only'
	content = render_to_string(
		'core/fund_request_records_pdf.html',
		{
			'records': records_queryset,
			'generated_at': generated_at,
			'generated_by_label': generated_by_label,
			'scope_label': scope_label,
			'filter_summary': records_context['filter_summary'],
		},
	)
	pdf_bytes = _render_html_bytes_to_pdf(content.encode('utf-8'), 'fund-request-records.html')
	if not pdf_bytes:
		return HttpResponse('PDF download is not available for this report right now.', content_type='text/plain; charset=utf-8', status=415)

	response = HttpResponse(pdf_bytes, content_type='application/pdf')
	response['Content-Disposition'] = f'attachment; filename="fund_request_records_{filename_stamp}.pdf"'
	return response


@login_required
def fund_request_records_csv(request):
	return fund_request_records_pdf(request)


@login_required
def finance_dashboard(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	can_approve_fund_requests = _can_approve_fund_requests(request.user)
	can_approve_liquidations = _can_approve_liquidations(request.user)

	approved_fund_requests_queryset = FundRequest.objects.select_related('created_by', 'processed_by').filter(request_status='approved')
	if not can_approve_fund_requests:
		approved_fund_requests_queryset = approved_fund_requests_queryset.filter(created_by=request.user)

	approved_liquidations_queryset = Liquidation.objects.select_related('created_by', 'processed_by').filter(request_status='approved')
	if not can_approve_liquidations:
		approved_liquidations_queryset = approved_liquidations_queryset.filter(created_by=request.user)

	context = {
		'approved_fund_request_count': approved_fund_requests_queryset.count(),
		'approved_liquidation_count': approved_liquidations_queryset.count(),
		'recent_fund_requests': approved_fund_requests_queryset.order_by('-created_at')[:5],
		'recent_liquidations': approved_liquidations_queryset.order_by('-created_at')[:5],
	}
	return render(request, 'core/finance_dashboard.html', context)


@login_required
def finance_reimburstment(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response
	return render(request, 'core/finance_reimburstment.html')


@login_required
def finance_summary_request(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response
	return render(request, 'core/finance_summary_request.html')


@login_required
def liquidation_page(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	can_approve_liquidations = _can_approve_liquidations(request.user)
	can_view_all_request_records = can_approve_liquidations
	can_add_liquidation = request.user.is_superuser or request.user.has_perm('core.add_liquidation')
	can_delete_liquidation = request.user.is_superuser or request.user.has_perm('core.delete_liquidation')
	can_manage_templates = _can_manage_liquidation_templates(request.user)
	liquidation_settings = LiquidationSettings.load()
	max_selectable_rows = int(liquidation_settings.max_selectable_rows or 20)

	active_template = LiquidationTemplate.objects.filter(is_active=True).order_by('-updated_at', '-created_at').first()
	all_templates = list(
		LiquidationTemplate.objects.select_related('uploaded_by', 'uploaded_by__profile').order_by('-is_active', '-updated_at', '-created_at')
	)

	if request.method == 'POST':
		action_type = (request.POST.get('action_type') or '').strip()
		template_action = (request.POST.get('template_action') or '').strip()
		template_action_id = ''
		if template_action:
			action_name, _, action_id = template_action.partition(':')
			template_action_id = action_id.strip()
			if action_name == 'set_default':
				action_type = 'set_default_template'
			elif action_name == 'delete':
				action_type = 'delete_template'
		if not action_type:
			action_type = 'create_liquidation'

		if action_type == 'upload_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to upload liquidation templates.')
			template_form = LiquidationTemplateForm(request.POST, request.FILES)
			liquidation_form = LiquidationForm(initial={'liquidation_date': timezone.localdate()}, user=request.user)
			if template_form.is_valid():
				template_record = template_form.save(commit=False)
				template_record.uploaded_by = request.user
				template_record.save()
				messages.success(request, f'Liquidation template "{template_record.name}" uploaded successfully.')
				return redirect('liquidation_page')
		elif action_type == 'set_default_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to update liquidation templates.')
			template_id = template_action_id or (request.POST.get('template_id') or '').strip()
			if not template_id.isdigit():
				messages.warning(request, 'Select a valid liquidation template.')
				return redirect('liquidation_page')
			template_record = get_object_or_404(LiquidationTemplate, pk=int(template_id))
			if template_record.is_active:
				messages.info(request, f'"{template_record.name}" is already the default liquidation template.')
				return redirect('liquidation_page')
			template_record.is_active = True
			template_record.save(update_fields=['is_active'])
			messages.success(request, f'"{template_record.name}" is now the default liquidation template.')
			return redirect('liquidation_page')
		elif action_type == 'delete_template':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to remove liquidation templates.')
			template_id = template_action_id or (request.POST.get('template_id') or '').strip()
			if not template_id.isdigit():
				messages.warning(request, 'Select a valid liquidation template.')
				return redirect('liquidation_page')
			template_record = get_object_or_404(LiquidationTemplate, pk=int(template_id))
			template_name = template_record.name
			template_record.delete()
			_ensure_active_liquidation_template()
			messages.success(request, f'Liquidation template "{template_name}" removed successfully.')
			return redirect('liquidation_page')
		elif action_type == 'bulk_delete_liquidations':
			if not can_delete_liquidation:
				return _permission_denied_response(request, 'You do not have permission to delete saved liquidation forms.')

			selected_ids = [
				int(value)
				for value in request.POST.getlist('selected_liquidation_ids')
				if str(value).isdigit()
			]
			if not selected_ids:
				messages.warning(request, 'Select at least one liquidation form to delete.')
				return redirect('liquidation_page')

			deletable_queryset = Liquidation.objects.exclude(request_status='pending')
			if not can_view_all_request_records:
				deletable_queryset = deletable_queryset.filter(created_by=request.user)

			liquidations_to_delete = list(deletable_queryset.filter(pk__in=selected_ids))
			deleted_count = len(liquidations_to_delete)
			deletable_queryset.filter(pk__in=selected_ids).delete()

			if not deleted_count:
				messages.warning(request, 'No saved liquidation forms matched the selected records.')
				return redirect('liquidation_page')

			messages.success(request, f'{deleted_count} saved liquidation form(s) deleted successfully.')
			return redirect('liquidation_page')
		elif action_type == 'approve_liquidation':
			if not can_approve_liquidations:
				return _permission_denied_response(request, 'You do not have permission to approve liquidation forms.')
			liquidation_id = (request.POST.get('liquidation_id') or '').strip()
			reason = (request.POST.get('decision_reason') or '').strip()
			if not liquidation_id.isdigit():
				messages.warning(request, 'Select a valid liquidation form.')
				return redirect('liquidation_page')
			liquidation = get_object_or_404(Liquidation, pk=int(liquidation_id))
			if liquidation.request_status != 'pending':
				messages.warning(request, 'Only pending liquidation forms can be approved.')
				return redirect('liquidation_page')
			with transaction.atomic():
				liquidation.refresh_from_db()
				if liquidation.request_status != 'pending':
					messages.warning(request, 'Only pending liquidation forms can be approved.')
					return redirect('liquidation_page')
				liquidation.mark_approved(processed_by=request.user, reason=reason)
			messages.success(request, f'Liquidation approved with control number {liquidation.control_number}.')
			return redirect('liquidation_page')
		elif action_type == 'reject_liquidation':
			if not can_approve_liquidations:
				return _permission_denied_response(request, 'You do not have permission to reject liquidation forms.')
			liquidation_id = (request.POST.get('liquidation_id') or '').strip()
			reason = (request.POST.get('decision_reason') or '').strip()
			if not liquidation_id.isdigit():
				messages.warning(request, 'Select a valid liquidation form.')
				return redirect('liquidation_page')
			liquidation = get_object_or_404(Liquidation, pk=int(liquidation_id))
			if liquidation.request_status != 'pending':
				messages.warning(request, 'Only pending liquidation forms can be rejected.')
				return redirect('liquidation_page')
			with transaction.atomic():
				liquidation.refresh_from_db()
				if liquidation.request_status != 'pending':
					messages.warning(request, 'Only pending liquidation forms can be rejected.')
					return redirect('liquidation_page')
				liquidation.mark_rejected(processed_by=request.user, reason=reason)
			messages.success(request, 'Liquidation form rejected.')
			return redirect('liquidation_page')
		elif action_type == 'cancel_pending_liquidation':
			liquidation_id = (request.POST.get('liquidation_id') or '').strip()
			reason = (request.POST.get('decision_reason') or '').strip()
			if not liquidation_id.isdigit():
				messages.warning(request, 'Select a valid liquidation form.')
				return redirect('liquidation_page')
			liquidation = get_object_or_404(Liquidation, pk=int(liquidation_id))
			if liquidation.request_status != 'pending':
				messages.warning(request, 'Only pending liquidation forms can be cancelled.')
				return redirect('liquidation_page')
			if liquidation.created_by_id != request.user.id and not can_approve_liquidations:
				return _permission_denied_response(request, 'You do not have permission to cancel this liquidation form.')
			with transaction.atomic():
				liquidation.refresh_from_db()
				if liquidation.request_status != 'pending':
					messages.warning(request, 'Only pending liquidation forms can be cancelled.')
					return redirect('liquidation_page')
				cancel_reason = reason or 'Cancelled by requester.'
				liquidation.mark_rejected(processed_by=request.user, reason=cancel_reason)
			messages.success(request, 'Pending liquidation request cancelled.')
			return redirect('liquidation_page')
		elif action_type == 'bulk_pending_liquidation_decision':
			if not can_approve_liquidations:
				return _permission_denied_response(request, 'You do not have permission to process pending liquidation forms.')
			decision = (request.POST.get('decision') or '').strip().lower()
			if decision not in {'approve', 'reject'}:
				messages.warning(request, 'Select a valid bulk decision.')
				return redirect('liquidation_page')
			selected_ids = [
				int(value)
				for value in request.POST.getlist('selected_pending_liquidation_ids')
				if str(value).isdigit()
			]
			if not selected_ids:
				fallback_ids = (request.POST.get('selected_pending_ids') or '').strip()
				selected_ids = [int(value) for value in fallback_ids.split(',') if value.strip().isdigit()]
			if not selected_ids:
				messages.warning(request, 'Select at least one pending liquidation form.')
				return redirect('liquidation_page')

			reason = (request.POST.get('decision_reason') or '').strip()
			pending_queryset = Liquidation.objects.filter(pk__in=selected_ids, request_status='pending')
			processed_count = 0
			with transaction.atomic():
				for liquidation in pending_queryset.select_for_update():
					if liquidation.request_status != 'pending':
						continue
					if decision == 'approve':
						liquidation.mark_approved(processed_by=request.user, reason=reason)
					else:
						liquidation.mark_rejected(processed_by=request.user, reason=reason)
					processed_count += 1

			if not processed_count:
				messages.warning(request, 'No pending liquidation forms were processed.')
				return redirect('liquidation_page')
			if decision == 'approve':
				messages.success(request, f'{processed_count} pending liquidation form(s) approved.')
			else:
				messages.success(request, f'{processed_count} pending liquidation form(s) rejected.')
			return redirect('liquidation_page')
		elif action_type == 'update_liquidation_settings':
			if not can_manage_templates:
				return _permission_denied_response(request, 'You do not have permission to update liquidation settings.')
			raw_limit = (request.POST.get('max_selectable_rows') or '').strip()
			try:
				parsed_limit = int(raw_limit)
			except (TypeError, ValueError):
				messages.warning(request, 'Enter a valid max row limit.')
				return redirect('liquidation_page')

			if parsed_limit < 1 or parsed_limit > 200:
				messages.warning(request, 'Max row limit must be between 1 and 200.')
				return redirect('liquidation_page')

			liquidation_settings.max_selectable_rows = parsed_limit
			liquidation_settings.save(update_fields=['max_selectable_rows', 'updated_at'])
			messages.success(request, f'Liquidation max row limit updated to {parsed_limit}.')
			return redirect('liquidation_page')
		else:
			if not can_add_liquidation:
				return _permission_denied_response(request, 'You do not have permission to create liquidation forms.')

			liquidation_form = LiquidationForm(request.POST, request.FILES, user=request.user)
			template_form = LiquidationTemplateForm()
			selected_template_id = (request.POST.get('selected_template_id') or '').strip()
			selected_template = LiquidationTemplate.objects.filter(pk=int(selected_template_id)).first() if selected_template_id.isdigit() else None
			if not selected_template:
				liquidation_form.add_error(None, 'Select an uploaded liquidation template before saving.')
			elif len(liquidation_form.get_line_items()) > max_selectable_rows:
				liquidation_form.add_error('line_items_payload', f'You can select up to {max_selectable_rows} item(s) only.')

			if liquidation_form.is_valid() and selected_template:
				try:
					with transaction.atomic():
						liquidation = liquidation_form.save(commit=False)
						liquidation.created_by = request.user
						liquidation.template = selected_template
						liquidation.request_status = 'pending'
						liquidation.save()
						liquidation_form.save_line_items(liquidation)
						liquidation_form.save_attachments(liquidation, uploaded_by=request.user)
				except IntegrityError:
					liquidation_form.add_error(None, 'One or more selected line items were already used in another liquidation.')
				else:
					messages.success(request, 'Liquidation form submitted for approval.')
					return redirect('liquidation_page')
	else:
		liquidation_form = LiquidationForm(initial={'liquidation_date': timezone.localdate()}, user=request.user)
		template_form = LiquidationTemplateForm()

	visible_approved_requests = FundRequest.objects.select_related('created_by', 'created_by__profile').filter(request_status='approved')
	if not can_view_all_request_records:
		visible_approved_requests = visible_approved_requests.filter(created_by=request.user)

	# Safety cleanup for historical rejected/cancelled records created before source-line release logic existed.
	LiquidationLineItem.objects.filter(
		liquidation__request_status__in=['rejected', 'cancelled']
	).exclude(
		source_line_item_id__isnull=True
	).update(source_line_item=None)

	used_source_ids = set(
		LiquidationLineItem.objects.filter(
			liquidation__request_status__in=['pending', 'approved']
		).exclude(
			source_line_item_id__isnull=True
		).values_list('source_line_item_id', flat=True)
	)
	available_source_items = list(
		FundRequestLineItem.objects.select_related('fund_request')
		.filter(fund_request__in=visible_approved_requests)
		.exclude(id__in=used_source_ids)
		.order_by('-fund_request__created_at', 'id')
	)

	liquidations_queryset = Liquidation.objects.select_related('template', 'created_by', 'created_by__profile').prefetch_related('items', 'attachments')
	if not can_view_all_request_records:
		liquidations_queryset = liquidations_queryset.filter(created_by=request.user)

	branch_filter_options = sorted(
		{
			(branch or '').strip()
			for branch in liquidations_queryset.values_list('branch', flat=True)
			if (branch or '').strip()
		}
	)

	pending_query = (request.GET.get('pending_q') or '').strip()
	pending_branch_filter = (request.GET.get('pending_branch') or '').strip()
	saved_query = (request.GET.get('saved_q') or '').strip()
	saved_branch_filter = (request.GET.get('saved_branch') or '').strip()
	saved_status_filter = (request.GET.get('saved_status') or '').strip().lower()
	if saved_status_filter not in {'approved', 'rejected'}:
		saved_status_filter = ''

	pending_liquidations_queryset = liquidations_queryset.filter(request_status='pending')
	if pending_query:
		pending_liquidations_queryset = pending_liquidations_queryset.filter(
			Q(name__icontains=pending_query)
			| Q(branch__icontains=pending_query)
			| Q(position__icontains=pending_query)
			| Q(requested_by_name__icontains=pending_query)
		)
	if pending_branch_filter:
		pending_liquidations_queryset = pending_liquidations_queryset.filter(branch=pending_branch_filter)

	saved_liquidations_queryset = liquidations_queryset.exclude(request_status='pending')
	if saved_query:
		saved_liquidations_queryset = saved_liquidations_queryset.filter(
			Q(control_number__icontains=saved_query)
			| Q(name__icontains=saved_query)
			| Q(branch__icontains=saved_query)
			| Q(position__icontains=saved_query)
			| Q(requested_by_name__icontains=saved_query)
		)
	if saved_branch_filter:
		saved_liquidations_queryset = saved_liquidations_queryset.filter(branch=saved_branch_filter)
	if saved_status_filter:
		saved_liquidations_queryset = saved_liquidations_queryset.filter(request_status=saved_status_filter)

	pending_liquidations_queryset = pending_liquidations_queryset.order_by('-created_at')
	saved_liquidations_queryset = saved_liquidations_queryset.order_by('-created_at')
	pending_liquidations_page = Paginator(pending_liquidations_queryset, 10).get_page(request.GET.get('pending_page'))
	saved_liquidations_page = Paginator(saved_liquidations_queryset, 10).get_page(request.GET.get('saved_page'))

	pending_page_query = request.GET.copy()
	if 'pending_page' in pending_page_query:
		del pending_page_query['pending_page']
	saved_page_query = request.GET.copy()
	if 'saved_page' in saved_page_query:
		del saved_page_query['saved_page']

	context = {
		'liquidation_form': liquidation_form,
		'template_form': template_form,
		'all_templates': all_templates,
		'active_template': active_template,
		'default_selected_template_id': active_template.id if active_template else '',
		'available_source_items': available_source_items,
		'pending_liquidations_page': pending_liquidations_page,
		'saved_liquidations_page': saved_liquidations_page,
		'total_pending_liquidations': pending_liquidations_queryset.count(),
		'total_saved_liquidations': saved_liquidations_queryset.count(),
		'pending_q': pending_query,
		'pending_branch': pending_branch_filter,
		'saved_q': saved_query,
		'saved_branch': saved_branch_filter,
		'saved_status': saved_status_filter,
		'liquidation_branch_filter_options': branch_filter_options,
		'pending_page_query': pending_page_query.urlencode(),
		'saved_page_query': saved_page_query.urlencode(),
		'can_add_liquidation': can_add_liquidation,
		'can_delete_liquidation': can_delete_liquidation,
		'can_manage_templates': can_manage_templates,
		'can_approve_liquidations': can_approve_liquidations,
		'can_view_all_request_records': can_view_all_request_records,
		'liquidation_max_selectable_rows': max_selectable_rows,
		'liquidation_placeholder_guide': _build_liquidation_template_placeholder_guide(),
	}
	return render(request, 'core/liquidation.html', context)


@login_required
def liquidation_pdf(request, liquidation_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	can_view_all_request_records = _can_approve_liquidations(request.user)
	queryset = Liquidation.objects.select_related('template', 'created_by').prefetch_related('items', 'attachments')
	if not can_view_all_request_records:
		queryset = queryset.filter(created_by=request.user)
	liquidation = get_object_or_404(queryset, pk=liquidation_id)

	payload = _build_liquidation_pdf_payload(liquidation, allow_structured_preview_fallback=True)
	if not payload:
		return HttpResponse('PDF preview is not available for this liquidation form.', content_type='text/plain; charset=utf-8', status=415)

	response = HttpResponse(payload['content'], content_type='application/pdf')
	response['Content-Disposition'] = f'inline; filename="{payload["filename"]}"'
	return response


@login_required
def liquidation_download(request, liquidation_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	can_view_all_request_records = _can_approve_liquidations(request.user)
	queryset = Liquidation.objects.select_related('template', 'created_by').prefetch_related('items', 'attachments')
	if not can_view_all_request_records:
		queryset = queryset.filter(created_by=request.user)
	liquidation = get_object_or_404(queryset, pk=liquidation_id)

	payload = _build_liquidation_pdf_payload(liquidation, allow_structured_preview_fallback=False)
	if not payload:
		messages.error(request, 'Unable to convert this liquidation form to PDF right now.', extra_tags='toast')
		return redirect('liquidation_page')

	response = HttpResponse(payload['content'], content_type='application/pdf')
	response['Content-Disposition'] = f'attachment; filename="{payload["filename"]}"'
	return response


@login_required
def liquidation_bulk_download(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	raw_selected_ids = (request.GET.get('selected_ids') or '').strip()
	selected_ids = [
		int(segment.strip())
		for segment in raw_selected_ids.split(',')
		if segment.strip().isdigit()
	]
	if not selected_ids:
		return HttpResponse('No liquidation forms selected for download.', content_type='text/plain; charset=utf-8', status=400)

	can_view_all_request_records = _can_approve_liquidations(request.user)
	queryset = Liquidation.objects.select_related('template', 'created_by').prefetch_related('items', 'attachments').filter(pk__in=selected_ids)
	if not can_view_all_request_records:
		queryset = queryset.filter(created_by=request.user)
	liquidation_map = {entry.pk: entry for entry in queryset}
	visible_liquidations = [liquidation_map[entry_id] for entry_id in selected_ids if entry_id in liquidation_map]
	if not visible_liquidations:
		return HttpResponse('No accessible liquidation forms were selected for download.', content_type='text/plain; charset=utf-8', status=404)

	pdf_parts = []
	for liquidation in visible_liquidations:
		payload = _build_liquidation_pdf_payload(liquidation, allow_structured_preview_fallback=False)
		if payload and payload.get('content'):
			pdf_parts.append(payload['content'])

	merged_pdf = _merge_pdf_parts(pdf_parts)
	if not merged_pdf:
		return HttpResponse('Unable to generate a downloadable PDF for the selected liquidation forms.', content_type='text/plain; charset=utf-8', status=415)

	filename_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
	response = HttpResponse(merged_pdf, content_type='application/pdf')
	response['Content-Disposition'] = f'attachment; filename="liquidations_selected_{filename_stamp}.pdf"'
	return response


@login_required
def liquidation_bulk_print(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	raw_selected_ids = (request.GET.get('selected_ids') or '').strip()
	selected_ids = [
		int(segment.strip())
		for segment in raw_selected_ids.split(',')
		if segment.strip().isdigit()
	]
	if not selected_ids:
		return HttpResponse('No liquidation forms selected for print.', content_type='text/plain; charset=utf-8', status=400)

	can_view_all_request_records = _can_approve_liquidations(request.user)
	queryset = Liquidation.objects.select_related('template', 'created_by').prefetch_related('items', 'attachments').filter(pk__in=selected_ids)
	if not can_view_all_request_records:
		queryset = queryset.filter(created_by=request.user)
	liquidation_map = {entry.pk: entry for entry in queryset}
	visible_liquidations = [liquidation_map[entry_id] for entry_id in selected_ids if entry_id in liquidation_map]
	if not visible_liquidations:
		return HttpResponse('No accessible liquidation forms were selected for print.', content_type='text/plain; charset=utf-8', status=404)

	pdf_parts = []
	for liquidation in visible_liquidations:
		payload = _build_liquidation_pdf_payload(liquidation, allow_structured_preview_fallback=False)
		if payload and payload.get('content'):
			pdf_parts.append(payload['content'])

	merged_pdf = _merge_pdf_parts(pdf_parts)
	if not merged_pdf:
		return HttpResponse('Unable to generate a printable PDF for the selected liquidation forms.', content_type='text/plain; charset=utf-8', status=415)

	filename_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
	response = HttpResponse(merged_pdf, content_type='application/pdf')
	response['Content-Disposition'] = f'inline; filename="liquidations_selected_{filename_stamp}.pdf"'
	return response


@login_required
def fund_request_review(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	get_object_or_404(FundRequest, pk=request_id)
	return redirect('fund_request_review_pdf', request_id=request_id)


@login_required
def fund_request_review_pdf(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	fund_request = get_object_or_404(
		FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments'),
		pk=request_id,
	)
	payload = _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=True)
	if not payload:
		return HttpResponse('PDF preview is not available for this fund request.', content_type='text/plain; charset=utf-8', status=415)

	response = HttpResponse(payload['content'], content_type='application/pdf')
	response['Content-Disposition'] = f'inline; filename="{payload["filename"]}"'
	return response


@login_required
def fund_request_document(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	fund_request = get_object_or_404(
		FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments'),
		pk=request_id,
	)
	if fund_request.request_status != 'approved':
		messages.warning(request, 'Only approved fund requests can be opened or printed.')
		return redirect('fund_requests_list')
	template_payload = _build_fund_request_template_file_payload(fund_request)
	if template_payload:
		response = HttpResponse(template_payload['content'], content_type=template_payload['content_type'])
		response['Content-Disposition'] = f'inline; filename="{template_payload["filename"]}"'
		return response

	messages.error(request, 'No template file is attached to this approved fund request.')
	return redirect('fund_requests_list')


@login_required
def fund_request_print(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	fund_request = get_object_or_404(
		FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments'),
		pk=request_id,
	)
	if fund_request.request_status != 'approved':
		messages.warning(request, 'Only approved fund requests can be printed.')
		return redirect('fund_requests_list')
	template_record = fund_request.template
	if not template_record or not getattr(template_record, 'file', None):
		messages.error(request, 'No preferred template file is attached to this approved fund request.')
		return redirect('fund_requests_list')

	payload = _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=False)
	if payload:
		response = HttpResponse(payload['content'], content_type='application/pdf')
		response['Content-Disposition'] = f'inline; filename="{payload["filename"]}"'
		return response

	client_side_payload = _build_fund_request_client_side_conversion_payload(fund_request)
	if client_side_payload:
		return redirect('fund_request_client_side_preview', request_id=fund_request.pk)

	template_extension = _fund_request_template_extension(template_record)
	convertible_extensions = {'.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html', '.xls', '.xlsx', '.xlsm', '.xlsb', '.csv'}
	if template_extension in convertible_extensions:
		backend_status = _office_conversion_backend_status(template_extension)
		if not any(backend_status.values()):
			messages.error(
				request,
				'No server-side converter is available. Install at least one of: (1) Microsoft Office, (2) libreoffice, (3) soffice.',
				extra_tags='toast',
			)
			return redirect('fund_requests_list')

	messages.error(
		request,
		'Unable to convert the filled template to PDF on the server. Checked sequence: (1) Microsoft Office, (2) libreoffice, (3) soffice.',
		extra_tags='toast',
	)
	return redirect('fund_requests_list')


@login_required
def fund_request_client_side_preview(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	fund_request = get_object_or_404(
		FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments'),
		pk=request_id,
	)
	if fund_request.request_status != 'approved':
		messages.warning(request, 'Only approved fund requests can be opened or printed.')
		return redirect('fund_requests_list')

	client_payload = _build_fund_request_client_side_conversion_payload(fund_request)
	if not client_payload:
		messages.error(
			request,
			'Client-side conversion fallback is currently available for DOCX and XLSX templates only.',
			extra_tags='toast',
		)
		return redirect('fund_requests_list')

	return render(
		request,
		'core/fund_request_client_side_preview.html',
		{
			'fund_request': fund_request,
			'template_record': fund_request.template,
			'template_extension': client_payload['extension'],
			'source_filename': client_payload['filename'],
			'source_content_b64': client_payload['content_b64'],
		},
	)


@login_required
def fund_request_template_preview(request, template_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	template_record = get_object_or_404(
		FundRequestTemplate.objects.select_related('uploaded_by', 'uploaded_by__profile'),
		pk=template_id,
	)
	return render(
		request,
		'core/fund_request_template_preview.html',
		_build_fund_request_template_preview_page_context(template_record),
	)


@login_required
def fund_request_template_preview_pdf(request, template_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	template_record = get_object_or_404(FundRequestTemplate, pk=template_id)
	payload = _build_template_preview_pdf_payload(template_record)
	if not payload:
		template_name = template_record.name or Path(getattr(template_record.file, 'name', '')).stem or 'Fund Request Template'
		original_name = Path(getattr(template_record.file, 'name', '')).name or 'uploaded template'
		notice_pdf = _build_notice_pdf_bytes(
			f'{template_name} Preview Unavailable',
			[
				f'The portal could not generate a PDF preview for {original_name}.',
				'This usually means the file could not be converted to PDF on the server.',
				'You can still use Open Original File on the template preview page.',
				'For the most reliable preview, use PDF, DOCX, or XLSX templates.',
			],
		)
		if notice_pdf:
			payload = {
				'content': notice_pdf,
				'filename': f'{Path(original_name).stem or "fund-request-template"}-preview-unavailable.pdf',
			}
		else:
			return HttpResponse('PDF preview is not available for this template.', content_type='text/plain; charset=utf-8', status=415)

	response = HttpResponse(payload['content'], content_type='application/pdf')
	response['Content-Disposition'] = f'inline; filename="{payload["filename"]}"'
	return response


@login_required
def fund_request_document_download(request, request_id):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	fund_request = get_object_or_404(
		FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments'),
		pk=request_id,
	)
	if fund_request.request_status != 'approved':
		messages.warning(request, 'Only approved fund requests can be downloaded.')
		return redirect('fund_requests_list')

	is_forced_download = (request.GET.get('download') or '').strip() == '1'
	payload = _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=False)
	if not payload:
		client_side_payload = _build_fund_request_client_side_conversion_payload(fund_request)
		if client_side_payload:
			return redirect('fund_request_client_side_preview', request_id=fund_request.pk)

		template_extension = _fund_request_template_extension(fund_request.template)
		convertible_extensions = {'.doc', '.docx', '.docm', '.rtf', '.txt', '.htm', '.html', '.xls', '.xlsx', '.xlsm', '.xlsb', '.csv'}
		if template_extension in convertible_extensions:
			backend_status = _office_conversion_backend_status(template_extension)
			if not any(backend_status.values()):
				messages.error(
					request,
					'No server-side converter is available. Install at least one of: (1) Microsoft Office, (2) libreoffice, (3) soffice.',
					extra_tags='toast',
				)
				return redirect('fund_requests_list')

		messages.error(
			request,
			'Unable to convert the filled template to PDF on the server. Checked sequence: (1) Microsoft Office, (2) libreoffice, (3) soffice.',
			extra_tags='toast',
		)
		return redirect('fund_requests_list')

	disposition = 'attachment' if is_forced_download else 'inline'
	response = HttpResponse(payload['content'], content_type='application/pdf')
	response['Content-Disposition'] = f'{disposition}; filename="{payload["filename"]}"'
	return response


def _parse_fund_request_selected_ids(raw_selected_ids):
	if not raw_selected_ids:
		return []
	return [
		int(segment.strip())
		for segment in str(raw_selected_ids).split(',')
		if str(segment).strip().isdigit()
	]


def _get_visible_approved_fund_requests_for_bulk_action(request, selected_ids):
	can_view_all_request_records = request.user.is_superuser or _can_approve_fund_requests(request.user)
	queryset = FundRequest.objects.select_related('created_by', 'created_by__profile', 'template').prefetch_related('items', 'attachments')
	queryset = queryset.filter(request_status='approved', pk__in=selected_ids)
	if not can_view_all_request_records:
		queryset = queryset.filter(created_by=request.user)
	request_map = {entry.pk: entry for entry in queryset}
	return [request_map[request_id] for request_id in selected_ids if request_id in request_map]


@login_required
def fund_request_bulk_print(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	selected_ids = _parse_fund_request_selected_ids((request.GET.get('selected_ids') or '').strip())
	if not selected_ids:
		return HttpResponse('No approved fund requests selected for print.', content_type='text/plain; charset=utf-8', status=400)

	visible_requests = _get_visible_approved_fund_requests_for_bulk_action(request, selected_ids)
	if not visible_requests:
		return HttpResponse('No accessible approved fund requests were selected for print.', content_type='text/plain; charset=utf-8', status=404)

	pdf_parts = []
	for fund_request in visible_requests:
		payload = _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=False)
		if payload and payload.get('content'):
			pdf_parts.append(payload['content'])

	merged_pdf = _merge_pdf_parts(pdf_parts)
	if not merged_pdf:
		return HttpResponse('Unable to generate a printable PDF for the selected requests.', content_type='text/plain; charset=utf-8', status=415)

	filename_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
	response = HttpResponse(merged_pdf, content_type='application/pdf')
	response['Content-Disposition'] = f'inline; filename="fund_requests_selected_{filename_stamp}.pdf"'
	return response


@login_required
def fund_request_bulk_download(request):
	restricted_response = _require_permission(request, 'core.view_fundrequest')
	if restricted_response:
		return restricted_response

	selected_ids = _parse_fund_request_selected_ids((request.GET.get('selected_ids') or '').strip())
	if not selected_ids:
		return HttpResponse('No approved fund requests selected for download.', content_type='text/plain; charset=utf-8', status=400)

	visible_requests = _get_visible_approved_fund_requests_for_bulk_action(request, selected_ids)
	if not visible_requests:
		return HttpResponse('No accessible approved fund requests were selected for download.', content_type='text/plain; charset=utf-8', status=404)

	pdf_parts = []
	for fund_request in visible_requests:
		payload = _build_fund_request_pdf_payload(fund_request, allow_structured_preview_fallback=False)
		if payload and payload.get('content'):
			pdf_parts.append(payload['content'])

	merged_pdf = _merge_pdf_parts(pdf_parts)
	if not merged_pdf:
		return HttpResponse('Unable to generate a downloadable PDF for the selected requests.', content_type='text/plain; charset=utf-8', status=415)

	filename_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d_%H%M%S')
	response = HttpResponse(merged_pdf, content_type='application/pdf')
	response['Content-Disposition'] = f'attachment; filename="fund_requests_selected_{filename_stamp}.pdf"'
	return response


@login_required
def clients_quick_view(request, client_id):
	can_view_client = request.user.is_superuser or request.user.has_perm('core.view_client')
	can_review_deletion = request.user.has_perm('core.approve_clientdeletionrequest')
	if not (can_view_client or can_review_deletion):
		return _permission_denied_response(request, 'You do not have permission to perform this action.')

	client = get_object_or_404(
		_filter_clients_by_visibility(
			request,
			Client.objects.select_related('handled_by', 'handled_by__profile', 'created_by').prefetch_related('quotations__documents')
		),
		pk=client_id,
	)
	quotations = list(
		client.quotations
		.select_related('sent_by')
		.prefetch_related('documents')
		.order_by('-version', '-sent_at')
	)
	latest_quotation = client.quotations.select_related('sent_by').order_by('-version', '-sent_at').first()
	handled_by_profile = getattr(client.handled_by, 'profile', None) if client.handled_by else None

	html = render_to_string(
		'core/includes/client_quick_view_modal_content.html',
		{
			'client': client,
			'latest_quotation': latest_quotation,
			'quotations': quotations,
			'handled_by_profile': handled_by_profile,
		},
		request=request,
	)
	return JsonResponse({'ok': True, 'html': html})


@login_required
def clients_quote(request, client_id):
	restricted_response = _require_permission(request, 'core.view_client')
	if restricted_response:
		return restricted_response

	client = get_object_or_404(
		_filter_clients_by_visibility(request, Client.objects.select_related('handled_by')),
		pk=client_id,
	)
	quotations = client.quotations.select_related('sent_by', 'sent_by__profile').prefetch_related('documents').order_by('-version', '-sent_at')
	latest_version = quotations.first().version if quotations.exists() else 0

	quotation_sender_profile_map = {}
	for quotation in quotations:
		sender = quotation.sent_by
		if sender and sender.id not in quotation_sender_profile_map:
			quotation_sender_profile_map[sender.id] = getattr(sender, 'profile', None)

	if request.method == 'POST':
		restricted_response = _require_permission(request, 'core.add_clientquotation')
		if restricted_response:
			return restricted_response

		form = ClientQuotationForm(request.POST, request.FILES)
		if form.is_valid():
			quotation = form.save(commit=False)
			lead_reason = (form.cleaned_data.get('lead_disposition_reason') or '').strip()
			if lead_reason:
				reason_note = f'Lead Status Reason: {lead_reason}'
				existing_notes = (quotation.quotation_notes or '').strip()
				quotation.quotation_notes = f'{existing_notes}\n\n{reason_note}' if existing_notes else reason_note
			quotation.client = client
			quotation.version = latest_version + 1
			quotation.sent_by = request.user
			quotation.save()

			for upload in form.cleaned_data.get('documents', []):
				ClientQuotationDocument.objects.create(
					quotation=quotation,
					file=upload,
					uploaded_by=request.user,
				)

			status_updates = {
				'sent': 'quotation_sent',
				'under_negotiation': 'negotiation',
				'accepted': 'closed_won',
				'rejected': 'closed_lost',
			}
			new_status = status_updates.get(quotation.negotiation_status, client.status)
			new_lead_status = form.cleaned_data.get('lead_status') or client.lead_status

			fields_to_update = []
			if client.status != new_status:
				client.status = new_status
				fields_to_update.append('status')
			if client.lead_status != new_lead_status:
				client.lead_status = new_lead_status
				fields_to_update.append('lead_status')

			if new_lead_status in {'lost', 'not_qualified'}:
				if (client.lead_disposition_reason or '').strip() != lead_reason:
					client.lead_disposition_reason = lead_reason
					fields_to_update.append('lead_disposition_reason')
			else:
				if (client.lead_disposition_reason or '').strip():
					client.lead_disposition_reason = ''
					fields_to_update.append('lead_disposition_reason')

			if fields_to_update:
				client.save(update_fields=fields_to_update)

			messages.success(request, f'Quotation v{quotation.version} sent and recorded successfully.')
			return redirect('clients_quote', client_id=client.id)
	else:
		initial = {}
		if quotations.exists():
			latest = quotations.first()
			initial = {
				'product_package': latest.product_package,
				'quoted_amount': latest.quoted_amount,
				'negotiation_status': latest.negotiation_status,
				'lead_status': client.lead_status,
				'lead_disposition_reason': client.lead_disposition_reason,
			}
		else:
			initial = {
				'lead_status': client.lead_status,
				'lead_disposition_reason': client.lead_disposition_reason,
			}
		form = ClientQuotationForm(initial=initial)

	context = {
		'client': client,
		'form': form,
		'quotations': quotations,
		'quotation_sender_profile_map': quotation_sender_profile_map,
		'next_version': latest_version + 1,
	}
	return render(request, 'core/client_quotation.html', context)


@login_required
def clients_quotation_document(request, client_id, quotation_id):
	restricted_response = _require_permission(request, 'core.view_client')
	if restricted_response:
		return restricted_response

	quotation_queryset = ClientQuotation.objects.select_related('client', 'sent_by', 'client__handled_by')
	if not _can_access_all_clients(request.user):
		quotation_queryset = quotation_queryset.filter(client__handled_by=request.user)

	quotation = get_object_or_404(
		quotation_queryset,
		pk=quotation_id,
		client_id=client_id,
	)

	context = {
		'quotation': quotation,
		'client': quotation.client,
		'documents': quotation.documents.all(),
	}
	return render(request, 'core/client_quotation_document.html', context)


@login_required
@require_POST
def clients_quotations_bulk_delete(request, client_id):
	restricted_response = _require_permission(request, 'core.delete_clientquotation')
	if restricted_response:
		return restricted_response

	client = get_object_or_404(_filter_clients_by_visibility(request), pk=client_id)
	quotation_ids = request.POST.getlist('quotation_ids')
	if not quotation_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			quotation_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in quotation_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No quotations selected.')
		return redirect('clients_quote', client_id=client.id)

	quotations = ClientQuotation.objects.filter(client=client, pk__in=parsed_ids)
	count = quotations.count()
	quotations.delete()

	if count:
		messages.success(request, f'{count} quotation(s) deleted successfully.')
	else:
		messages.warning(request, 'No matching quotations found.')

	return redirect('clients_quote', client_id=client.id)


@login_required
def clients_create(request):
	restricted_response = _require_permission(request, 'core.add_client')
	if restricted_response:
		return restricted_response

	is_modal_request = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('modal') == '1'
	handled_by_readonly_label = None if request.user.is_superuser else (request.user.get_full_name() or request.user.username)

	if request.method == 'POST':
		form = ClientForm(request.POST, request.FILES, current_user=request.user)
		if form.is_valid():
			client = form.save(commit=False)
			client.created_by = request.user
			client.status = 'inquiry'
			client.lead_status = 'intake'
			client.lead_disposition_reason = ''
			client.lead_proof_image = None
			if not client.handled_by:
				client.handled_by = request.user
			client.save()
			if is_modal_request:
				return JsonResponse({'ok': True, 'redirect_url': reverse('clients_list')})
			messages.success(request, 'Client created successfully.')
			return redirect('clients_list')

		if is_modal_request:
			html = render_to_string(
				'core/includes/client_form_modal_content.html',
				{
					'form': form,
					'page_title': 'Add Client',
					'submit_label': 'Save Client',
					'form_action': reverse('clients_create'),
					'handled_by_readonly_label': handled_by_readonly_label,
					'is_modal': True,
				},
				request=request,
			)
			return JsonResponse({'ok': False, 'html': html}, status=400)
	else:
		form = ClientForm(initial={'handled_by': request.user, 'handled_date': timezone.localdate()}, current_user=request.user)

	if is_modal_request:
		html = render_to_string(
			'core/includes/client_form_modal_content.html',
			{
				'form': form,
				'page_title': 'Add Client',
				'submit_label': 'Save Client',
				'form_action': reverse('clients_create'),
				'handled_by_readonly_label': handled_by_readonly_label,
				'is_modal': True,
			},
			request=request,
		)
		return JsonResponse({'ok': True, 'html': html})

	return render(
		request,
		'core/clients_form.html',
		{
			'form': form,
			'page_title': 'Add Client',
			'submit_label': 'Save Client',
			'form_action': reverse('clients_create'),
			'handled_by_readonly_label': handled_by_readonly_label,
			'is_modal': False,
		},
	)


@login_required
def clients_update(request, client_id):
	restricted_response = _require_permission(request, 'core.change_client')
	if restricted_response:
		return restricted_response

	client = get_object_or_404(Client, pk=client_id)
	is_modal_request = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.GET.get('modal') == '1'
	handled_by_readonly_label = None if request.user.is_superuser else (request.user.get_full_name() or request.user.username)
	if request.method == 'POST':
		form = ClientForm(request.POST, request.FILES, instance=client, current_user=request.user)
		if form.is_valid():
			updated_client = form.save(commit=False)
			updated_client.status = client.status
			updated_client.lead_status = client.lead_status
			updated_client.lead_disposition_reason = client.lead_disposition_reason
			updated_client.lead_proof_image = client.lead_proof_image
			updated_client.save()
			if is_modal_request:
				return JsonResponse({'ok': True, 'redirect_url': reverse('clients_list')})
			messages.success(request, 'Client updated successfully.')
			return redirect('clients_list')

		if is_modal_request:
			html = render_to_string(
				'core/includes/client_form_modal_content.html',
				{
					'form': form,
					'page_title': f'Edit Client: {client.full_name}',
					'submit_label': 'Save Changes',
					'form_action': reverse('clients_update', kwargs={'client_id': client.id}),
					'handled_by_readonly_label': handled_by_readonly_label,
					'is_modal': True,
				},
				request=request,
			)
			return JsonResponse({'ok': False, 'html': html}, status=400)
	else:
		form = ClientForm(instance=client, current_user=request.user)

	if is_modal_request:
		html = render_to_string(
			'core/includes/client_form_modal_content.html',
			{
				'form': form,
				'page_title': f'Edit Client: {client.full_name}',
				'submit_label': 'Save Changes',
				'form_action': reverse('clients_update', kwargs={'client_id': client.id}),
				'handled_by_readonly_label': handled_by_readonly_label,
				'is_modal': True,
			},
			request=request,
		)
		return JsonResponse({'ok': True, 'html': html})

	return render(
		request,
		'core/clients_form.html',
		{
			'form': form,
			'page_title': f'Edit Client: {client.full_name}',
			'submit_label': 'Save Changes',
			'form_action': reverse('clients_update', kwargs={'client_id': client.id}),
			'handled_by_readonly_label': handled_by_readonly_label,
			'is_modal': False,
		},
	)


@login_required
def clients_delete(request, client_id):
	restricted_response = _require_permission(request, 'core.delete_client')
	if restricted_response:
		return restricted_response

	client = get_object_or_404(Client, pk=client_id)
	if request.method == 'POST':
		reason = (request.POST.get('reason') or '').strip()
		if not reason:
			messages.warning(request, 'Please provide a reason for the deletion request.')
			return render(request, 'core/clients_confirm_delete.html', {'client': client})

		result, _deletion_request = _submit_client_deletion_request(client, request.user, reason=reason)
		if result == 'pending':
			messages.warning(request, f'Deletion request for "{client.full_name}" is already pending approval.')
		elif result == 'reopened':
			messages.success(request, f'Deletion request for "{client.full_name}" was resubmitted for approval.')
		else:
			messages.success(request, f'Deletion request for "{client.full_name}" submitted for approval.')
		return redirect('clients_list')

	return render(request, 'core/clients_confirm_delete.html', {'client': client})


@login_required
@require_POST
def clients_bulk_delete(request):
	restricted_response = _require_permission(request, 'core.delete_client')
	if restricted_response:
		return restricted_response

	client_ids = request.POST.getlist('client_ids')
	reason = (request.POST.get('reason') or '').strip()
	if not client_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			client_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	if not reason:
		messages.warning(request, 'Please provide a reason for the deletion request.')
		return redirect('clients_list')

	parsed_ids = []
	for raw_id in client_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No clients selected.')
		return redirect('clients_list')

	clients = list(Client.objects.filter(pk__in=parsed_ids).order_by('full_name'))
	if not clients:
		messages.warning(request, 'No matching clients found.')
		return redirect('clients_list')

	created_count = 0
	reopened_count = 0
	already_pending_count = 0
	for client in clients:
		result, _deletion_request = _submit_client_deletion_request(client, request.user, reason=reason)
		if result == 'pending':
			already_pending_count += 1
		elif result == 'reopened':
			reopened_count += 1
		else:
			created_count += 1

	if created_count:
		messages.success(request, f'{created_count} client deletion request(s) submitted for approval.')
	if reopened_count:
		messages.success(request, f'{reopened_count} previously rejected request(s) were resubmitted for approval.')
	if already_pending_count:
		messages.warning(request, f'{already_pending_count} selected client(s) already have pending deletion requests.')
	if not created_count and not reopened_count and not already_pending_count:
		messages.warning(request, 'No deletion requests were created.')

	return redirect('clients_list')


@login_required
@require_POST
def clients_deletion_request_approve(request, request_id):
	restricted_response = _require_permission(request, 'core.approve_clientdeletionrequest')
	if restricted_response:
		return restricted_response

	deletion_request = get_object_or_404(ClientDeletionRequest.objects.select_related('client', 'requested_by'), pk=request_id)
	if deletion_request.status != 'pending':
		messages.warning(request, 'This deletion request is no longer pending.')
		return redirect('clients_list')

	review_notes = (request.POST.get('review_notes') or '').strip()
	client_name = deletion_request.client_name_snapshot
	client = deletion_request.client

	if client:
		client_name = client.full_name
		client.delete()
		# Avoid keeping a stale in-memory reference to a deleted Client object.
		deletion_request.client = None

	deletion_request.status = 'approved'
	deletion_request.reviewed_by = request.user
	deletion_request.reviewed_at = timezone.now()
	deletion_request.review_notes = review_notes
	deletion_request.save(update_fields=['status', 'reviewed_by', 'reviewed_at', 'review_notes', 'client'])

	if deletion_request.requested_by and deletion_request.requested_by_id != request.user.id:
		create_notification(
			deletion_request.requested_by,
			title='Client deletion request approved',
			message=f'Your deletion request for "{client_name}" was approved.',
			link_url=reverse('clients_list'),
		)

	messages.success(request, f'Client deletion request approved for "{client_name}".')
	return redirect('clients_list')


@login_required
@require_POST
def clients_deletion_request_reject(request, request_id):
	restricted_response = _require_permission(request, 'core.approve_clientdeletionrequest')
	if restricted_response:
		return restricted_response

	deletion_request = get_object_or_404(ClientDeletionRequest.objects.select_related('client', 'requested_by'), pk=request_id)
	if deletion_request.status != 'pending':
		messages.warning(request, 'This deletion request is no longer pending.')
		return redirect('clients_list')

	review_notes = (request.POST.get('review_notes') or '').strip()
	if not review_notes:
		messages.warning(request, 'Please provide review notes when rejecting a deletion request.')
		return redirect('clients_list')

	deletion_request.status = 'rejected'
	deletion_request.reviewed_by = request.user
	deletion_request.reviewed_at = timezone.now()
	deletion_request.review_notes = review_notes
	deletion_request.save(update_fields=['status', 'reviewed_by', 'reviewed_at', 'review_notes'])

	if deletion_request.requested_by and deletion_request.requested_by_id != request.user.id:
		create_notification(
			deletion_request.requested_by,
			title='Client deletion request rejected',
			message=f'Your deletion request for "{deletion_request.client_name_snapshot}" was rejected.',
			link_url=reverse('clients_list'),
		)

	messages.info(request, f'Client deletion request rejected for "{deletion_request.client_name_snapshot}".')
	return redirect('clients_list')


@login_required
@require_POST
def clients_bulk_update_status(request):
	restricted_response = _require_permission(request, 'core.change_client')
	if restricted_response:
		return restricted_response

	status_value = (request.POST.get('status') or '').strip()
	allowed_statuses = {choice[0] for choice in Client.STATUS_CHOICES}
	if status_value not in allowed_statuses:
		messages.error(request, 'Please choose a valid client status.')
		return redirect('clients_list')

	client_ids = request.POST.getlist('client_ids')
	if not client_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			client_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in client_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No clients selected.')
		return redirect('clients_list')

	updated = Client.objects.filter(pk__in=parsed_ids).update(status=status_value)
	status_label_map = dict(Client.STATUS_CHOICES)
	status_label = status_label_map.get(status_value, status_value)

	if updated:
		messages.success(request, f'{updated} client(s) updated to "{status_label}".')
	else:
		messages.warning(request, 'No matching clients found.')

	return redirect('clients_list')


@login_required
def assets_list(request):
	restricted_response = _require_permission(request, 'core.view_assetitem')
	if restricted_response:
		return restricted_response

	it_department, _ = AssetDepartment.objects.get_or_create(name='IT', defaults={'is_default': True})
	if not it_department.is_default:
		it_department.is_default = True
		it_department.save(update_fields=['is_default'])

	query = (request.GET.get('q') or '').strip()
	selected_department = (request.GET.get('department') or '').strip()

	departments = AssetDepartment.objects.all().order_by('name')
	items = (
		AssetItem.objects
		.select_related('department')
		.prefetch_related('images')
		.filter(parent_item__isnull=True)
		.order_by('item_code', 'id')
	)

	if selected_department:
		items = items.filter(department_id=selected_department)
	if query:
		items = items.filter(
			Q(item_code__icontains=query)
			| Q(item_name__icontains=query)
			| Q(specification__icontains=query)
			| Q(department__name__icontains=query)
		)

	items_page = Paginator(items, 20).get_page(request.GET.get('page'))
	page_parent_items = list(items_page.object_list)
	parent_ids = [item.id for item in page_parent_items]

	variant_counts_map = {}
	parent_total_stock_map = {item.id: int(item.stock_quantity or 0) for item in page_parent_items}
	parent_stock_status_map = {}
	holder_summary_map = {}
	holder_entries_map = {}
	holder_hidden_count_map = {}
	holder_hidden_names_map = {}
	if parent_ids:
		variant_rows = AssetItem.objects.filter(parent_item_id__in=parent_ids).values('parent_item_id').annotate(total=Count('id'))
		variant_counts_map = {row['parent_item_id']: int(row['total'] or 0) for row in variant_rows}

		variant_stock_rows = AssetItem.objects.filter(parent_item_id__in=parent_ids).values('parent_item_id').annotate(total=Sum('stock_quantity'))
		for row in variant_stock_rows:
			parent_id = row.get('parent_item_id')
			if not parent_id:
				continue
			parent_total_stock_map[parent_id] = int(parent_total_stock_map.get(parent_id, 0) + (row.get('total') or 0))

		variant_id_rows = AssetItem.objects.filter(parent_item_id__in=parent_ids).values_list('id', 'parent_item_id')
		root_item_map = {parent_id: parent_id for parent_id in parent_ids}
		for variant_id, parent_id in variant_id_rows:
			root_item_map[variant_id] = parent_id

		active_borrowings = AssetAccountability.objects.filter(
			request_status='approved',
			status='borrowed',
			item_id__in=list(root_item_map.keys()),
		).select_related('borrowed_by', 'borrowed_by__profile').order_by('-date_borrowed')

		holder_names_map = {parent_id: [] for parent_id in parent_ids}
		holder_entries_map = {parent_id: [] for parent_id in parent_ids}
		for borrowing in active_borrowings:
			parent_id = root_item_map.get(borrowing.item_id)
			if not parent_id:
				continue
			holder_name = borrowing.borrowed_by.get_full_name() or borrowing.borrowed_by.username
			existing = holder_names_map.setdefault(parent_id, [])
			if holder_name not in existing:
				existing.append(holder_name)
				profile = getattr(borrowing.borrowed_by, 'profile', None)
				holder_entries_map.setdefault(parent_id, []).append(
					{
						'user_id': borrowing.borrowed_by_id,
						'name': holder_name,
						'avatar_url': profile.avatar.url if profile and profile.avatar else '',
						'avatar_initial': (holder_name[:1] or borrowing.borrowed_by.username[:1] or 'U').upper(),
					},
				)

		for parent_id, names in holder_names_map.items():
			if not names:
				holder_summary_map[parent_id] = '-'
				holder_hidden_count_map[parent_id] = 0
				holder_hidden_names_map[parent_id] = ''
			elif len(names) <= 2:
				holder_summary_map[parent_id] = ', '.join(names)
				holder_hidden_count_map[parent_id] = 0
				holder_hidden_names_map[parent_id] = ''
			else:
				holder_summary_map[parent_id] = ', '.join(names[:2])
				holder_hidden_count_map[parent_id] = len(names) - 2
				holder_hidden_names_map[parent_id] = ', '.join(names[2:])

	for item in page_parent_items:
		total_stock = int(parent_total_stock_map.get(item.id, 0))
		if total_stock == 0:
			parent_stock_status_map[item.id] = 'out of stock'
		elif total_stock <= int(item.low_stock_threshold or 0):
			parent_stock_status_map[item.id] = 'low stock'
		else:
			parent_stock_status_map[item.id] = 'instock'

	recent_batches = (
		AssetTagBatch.objects.select_related('department', 'generated_by', 'generated_by__profile')
		.annotate(total_tags=Count('entries'), total_item_codes=Count('entries__item_code_snapshot', distinct=True))
		.order_by('-created_at')
	)
	batches_page = Paginator(recent_batches, 20).get_page(request.GET.get('batch_page'))
	batch_generator_profiles_map = {}
	for batch in batches_page.object_list:
		generator = batch.generated_by
		if generator and generator.id not in batch_generator_profiles_map:
			batch_generator_profiles_map[generator.id] = getattr(generator, 'profile', None)

	context = {
		'departments': departments,
		'item_types': AssetItemType.objects.order_by('name'),
		'can_view_asset_tracker_category': (
			request.user.is_superuser
			or request.user.has_perm('core.view_assettrackercategory')
			or request.user.has_perm('core.view_assetitemtype')
		),
		'items_page': items_page,
		'variant_counts_map': variant_counts_map,
		'parent_total_stock_map': parent_total_stock_map,
		'parent_stock_status_map': parent_stock_status_map,
		'holder_summary_map': holder_summary_map,
		'holder_entries_map': holder_entries_map,
		'holder_hidden_count_map': holder_hidden_count_map,
		'holder_hidden_names_map': holder_hidden_names_map,
		'batches_page': batches_page,
		'batch_generator_profiles_map': batch_generator_profiles_map,
		'query': query,
		'selected_department': selected_department,
		'total_departments': departments.count(),
		'total_asset_codes': AssetItem.objects.count(),
		'total_variants': AssetItem.objects.filter(parent_item__isnull=False).count(),
		'total_stock_units': AssetItem.objects.aggregate(total=Sum('stock_quantity')).get('total') or 0,
	}
	return render(request, 'core/assets_list.html', context)


@login_required
def assets_company_accounts(request):
	can_manage_internet_accounts = _can_manage_company_internet_accounts(request.user)
	can_submit_internet_accounts = request.user.is_superuser or request.user.has_perm('core.add_companyinternetaccount')
	if not can_manage_internet_accounts and not can_submit_internet_accounts:
		return _permission_denied_response(request, 'You do not have permission to view this page.')

	internet_account_query = (request.GET.get('ia_q') or '').strip()
	internet_accounts = CompanyInternetAccount.objects.select_related('submitted_by', 'submitted_by__profile').order_by('-created_at')
	if not can_manage_internet_accounts:
		internet_accounts = internet_accounts.filter(submitted_by=request.user)
	if internet_account_query:
		internet_accounts = internet_accounts.filter(
			Q(platform_name__icontains=internet_account_query)
			| Q(account_identifier__icontains=internet_account_query)
			| Q(login_email__icontains=internet_account_query)
			| Q(credential_username__icontains=internet_account_query)
			| Q(holder_name_override__icontains=internet_account_query)
		)

	internet_accounts_page = Paginator(internet_accounts, 8).get_page(request.GET.get('account_page'))
	unlocked_ids = _get_unlocked_company_account_ids(request)
	unlocked_passwords_map = {}
	for account in internet_accounts_page.object_list:
		if account.id in unlocked_ids:
			unlocked_passwords_map[account.id] = account.get_credential_password()

	context = {
		'internet_account_query': internet_account_query,
		'can_manage_internet_accounts': can_manage_internet_accounts,
		'can_submit_internet_accounts': can_submit_internet_accounts,
		'company_internet_account_form': CompanyInternetAccountForm(),
		'internet_accounts_page': internet_accounts_page,
		'unlocked_passwords_map': unlocked_passwords_map,
		'company_account_unlock_form': CompanyInternetAccountUnlockForm(user=request.user),
	}
	return render(request, 'core/assets_company_accounts.html', context)


@login_required
@require_POST
def assets_company_account_submit(request):
	restricted_response = _require_permission(request, 'core.add_companyinternetaccount')
	if restricted_response:
		return restricted_response

	form = CompanyInternetAccountForm(request.POST)
	if form.is_valid():
		record = form.save(commit=False)
		record.submitted_by = request.user
		record.save()
		messages.success(request, f'Credential record for "{record.platform_name}" has been submitted.')
	else:
		for _, errors in form.errors.items():
			if errors:
				messages.error(request, errors[0])
				break

	next_url = (request.POST.get('next') or '').strip()
	if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}):
		return redirect(next_url)
	return redirect(f'{reverse("assets_company_accounts")}#companyInternetAccounts')


@login_required
@require_POST
def assets_company_account_reveal(request, account_id):
	account = get_object_or_404(CompanyInternetAccount.objects.select_related('submitted_by'), pk=account_id)
	can_manage = _can_manage_company_internet_accounts(request.user)
	if not can_manage and account.submitted_by_id != request.user.id:
		return _permission_denied_response(request, 'You do not have permission to view this credential.')

	action_type = (request.POST.get('credential_action') or 'unlock').strip().lower()
	if action_type == 'lock':
		_mark_company_account_locked(request, account.id)
		messages.success(request, f'Credential for "{account.platform_name}" is now masked.')
	else:
		unlock_form = CompanyInternetAccountUnlockForm(request.POST, user=request.user)
		if unlock_form.is_valid():
			_mark_company_account_unlocked(request, account.id)
			account.last_unlocked_at = timezone.now()
			account.save(update_fields=['last_unlocked_at'])
			messages.success(request, f'Credential for "{account.platform_name}" is now unlocked for viewing.')
		else:
			for _, errors in unlock_form.errors.items():
				if errors:
					messages.error(request, errors[0])
					break

	next_url = (request.POST.get('next') or '').strip()
	if next_url and url_has_allowed_host_and_scheme(next_url, {request.get_host()}):
		return redirect(next_url)
	return redirect(f'{reverse("assets_company_accounts")}#companyInternetAccounts')


@login_required
def assets_item_variants_modal(request, item_id):
	restricted_response = _require_permission(request, 'core.view_assetitem')
	if restricted_response:
		return restricted_response

	parent_item = get_object_or_404(
		AssetItem.objects.select_related('department'),
		pk=item_id,
		parent_item__isnull=True,
	)
	variants = list(
		AssetItem.objects.filter(parent_item=parent_item)
		.select_related('department')
		.prefetch_related('images')
		.order_by('item_code', 'id')
	)

	item_ids = [parent_item.id] + [item.id for item in variants]
	active_borrowings = AssetAccountability.objects.filter(
		request_status='approved',
		status='borrowed',
		item_id__in=item_ids,
	).select_related('borrowed_by').order_by('-date_borrowed')

	holders_by_item = {}
	for borrowing in active_borrowings:
		key = borrowing.item_id
		holder_name = borrowing.borrowed_by.get_full_name() or borrowing.borrowed_by.username
		holder_entry = f'{holder_name} ({borrowing.quantity_borrowed}x)'
		holders_by_item.setdefault(key, [])
		if holder_entry not in holders_by_item[key]:
			holders_by_item[key].append(holder_entry)

	variant_images_map = {}
	for variant in variants:
		entries = []
		seen_urls = set()
		for image_row in variant.images.all():
			if not image_row.image:
				continue
			url = image_row.image.url
			if url in seen_urls:
				continue
			seen_urls.add(url)
			entries.append(
				{
					'src': url,
					'name': (image_row.image.name or '').split('/')[-1] or f'{variant.item_code} image',
				}
			)

		if variant.asset_image:
			fallback_url = variant.asset_image.url
			if fallback_url not in seen_urls:
				entries.append(
					{
						'src': fallback_url,
						'name': (variant.asset_image.name or '').split('/')[-1] or f'{variant.item_code} image',
					}
				)

		variant_images_map[str(variant.id)] = entries

	parent_item_specification = (parent_item.specification or '').strip()
	parent_item_note = (parent_item.note or '').strip()
	has_parent_item_details = bool(
		parent_item.get_primary_image_url() or parent_item_specification or parent_item_note
	)

	html = render_to_string(
		'core/includes/assets_item_variants_modal_content.html',
		{
			'parent_item': parent_item,
			'parent_item_specification': parent_item_specification,
			'parent_item_note': parent_item_note,
			'has_parent_item_details': has_parent_item_details,
			'variants': variants,
			'holders_by_item': holders_by_item,
			'variant_images_map': variant_images_map,
		},
		request=request,
	)
	return JsonResponse({'ok': True, 'html': html})


@login_required
def assets_departments_list(request):
	restricted_response = _require_permission(request, 'core.view_assetdepartment')
	if restricted_response:
		return restricted_response

	query = (request.GET.get('q') or '').strip()
	departments = AssetDepartment.objects.annotate(asset_count=Count('assets')).order_by('name')
	if query:
		departments = departments.filter(name__icontains=query)

	page = Paginator(departments, 20).get_page(request.GET.get('page'))
	return render(request, 'core/assets_departments_list.html', {'departments_page': page, 'query': query})


@login_required
def assets_department_create(request):
	restricted_response = _require_permission(request, 'core.add_assetdepartment')
	if restricted_response:
		return restricted_response

	if request.method == 'POST':
		form = AssetDepartmentForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request, 'Department created successfully.')
			return redirect('assets_departments_list')
	else:
		form = AssetDepartmentForm()

	return render(
		request,
		'core/assets_department_form.html',
		{
			'form': form,
			'page_title': 'Create Department',
			'submit_label': 'Save Department',
			'cancel_url_name': 'assets_departments_list',
		},
	)


@login_required
def assets_department_update(request, department_id):
	restricted_response = _require_permission(request, 'core.change_assetdepartment')
	if restricted_response:
		return restricted_response

	department = get_object_or_404(AssetDepartment, pk=department_id)
	if request.method == 'POST':
		form = AssetDepartmentForm(request.POST, instance=department)
		if form.is_valid():
			form.save()
			messages.success(request, 'Department updated successfully.')
			return redirect('assets_departments_list')
	else:
		form = AssetDepartmentForm(instance=department)

	return render(
		request,
		'core/assets_department_form.html',
		{
			'form': form,
			'page_title': f'Edit Department: {department.name}',
			'submit_label': 'Save Changes',
			'cancel_url_name': 'assets_departments_list',
		},
	)


@login_required
def assets_department_delete(request, department_id):
	restricted_response = _require_permission(request, 'core.delete_assetdepartment')
	if restricted_response:
		return restricted_response

	department = get_object_or_404(AssetDepartment, pk=department_id)
	if request.method == 'POST':
		if department.is_default:
			messages.warning(request, 'Default department cannot be deleted.')
			return redirect('assets_departments_list')

		in_use = AssetItem.objects.filter(department=department).exists()
		if in_use:
			messages.error(request, 'This department is currently used by assets and cannot be deleted.')
			return redirect('assets_departments_list')

		department.delete()
		messages.success(request, 'Department deleted successfully.')
		return redirect('assets_departments_list')

	return render(request, 'core/assets_department_confirm_delete.html', {'department': department})


@login_required
@require_POST
def assets_departments_bulk_delete(request):
	restricted_response = _require_permission(request, 'core.delete_assetdepartment')
	if restricted_response:
		return restricted_response

	department_ids = request.POST.getlist('department_ids')
	if not department_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			department_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in department_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No departments selected for deletion.')
		return redirect('assets_departments_list')

	departments = AssetDepartment.objects.filter(pk__in=parsed_ids)
	deleted_count = 0
	default_count = 0
	in_use_count = 0

	for department in departments:
		if department.is_default:
			default_count += 1
			continue
		if AssetItem.objects.filter(department=department).exists():
			in_use_count += 1
			continue
		department.delete()
		deleted_count += 1

	if deleted_count:
		messages.success(request, f'{deleted_count} department(s) deleted successfully.')
	if default_count:
		messages.warning(request, f'{default_count} default department(s) were skipped.')
	if in_use_count:
		messages.warning(request, f'{in_use_count} department(s) are in use and could not be deleted.')

	return redirect('assets_departments_list')


@login_required
def assets_item_create(request):
	restricted_response = _require_permission(request, 'core.add_assetitem')
	if restricted_response:
		return restricted_response

	if request.method == 'POST':
		form = AssetItemForm(request.POST, request.FILES)
		if form.is_valid():
			asset_item = form.save(commit=False)
			asset_item.created_by = request.user
			asset_item.save()
			form.save_images(asset_item)
			messages.success(request, f'Asset saved with Item ID {asset_item.item_code}.')
			return redirect('assets_list')
	else:
		form = AssetItemForm()

	return render(
		request,
		'core/assets_item_form.html',
		{
			'form': form,
			'page_title': 'Create Asset Item',
			'submit_label': 'Save Item',
		},
	)


@login_required
def assets_item_update(request, item_id):
	restricted_response = _require_permission(request, 'core.change_assetitem')
	if restricted_response:
		return restricted_response

	item = get_object_or_404(AssetItem, pk=item_id)
	if request.method == 'POST':
		form = AssetItemForm(request.POST, request.FILES, instance=item)
		if form.is_valid():
			updated_item = form.save()
			form.save_images(updated_item)
			messages.success(request, f'Asset {updated_item.item_code} updated successfully.')
			return redirect('assets_list')
	else:
		form = AssetItemForm(instance=item)

	return render(
		request,
		'core/assets_item_form.html',
		{
			'form': form,
			'page_title': f'Edit Asset Item: {item.item_code}',
			'submit_label': 'Save Changes',
		},
	)


@login_required
def assets_item_delete(request, item_id):
	restricted_response = _require_permission(request, 'core.delete_assetitem')
	if restricted_response:
		return restricted_response

	item = get_object_or_404(AssetItem, pk=item_id)
	if request.method == 'POST':
		item_code = item.item_code
		item.delete()
		messages.success(request, f'Asset {item_code} deleted successfully.')
		return redirect('assets_list')

	return render(request, 'core/assets_item_confirm_delete.html', {'item': item})


@login_required
@require_POST
def assets_items_bulk_delete(request):
	restricted_response = _require_permission(request, 'core.delete_assetitem')
	if restricted_response:
		return restricted_response

	item_ids = request.POST.getlist('item_ids')
	if not item_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			item_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]
	parsed_ids = []
	for raw_id in item_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No items selected for deletion.')
		return redirect('assets_list')

	items_to_delete = AssetItem.objects.filter(pk__in=parsed_ids)
	deleted_count = 0
	failed_count = 0
	for item in items_to_delete:
		try:
			item.delete()
			deleted_count += 1
		except Exception:
			failed_count += 1

	if deleted_count:
		messages.success(request, f'{deleted_count} item(s) deleted successfully.')
	if failed_count:
		messages.warning(
			request,
			f'{failed_count} item(s) could not be deleted. Delete variants/related references first.',
		)

	return redirect('assets_list')


@login_required
@require_POST
def assets_variants_bulk_delete(request, item_id):
	restricted_response = _require_permission(request, 'core.delete_assetitem')
	if restricted_response:
		return restricted_response

	parent_item = get_object_or_404(AssetItem, pk=item_id, parent_item__isnull=True)
	item_ids = request.POST.getlist('item_ids')
	parsed_ids = []
	for raw_id in item_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No variants selected for deletion.')
		return redirect('assets_list')

	variants_to_delete = AssetItem.objects.filter(parent_item=parent_item, pk__in=parsed_ids)
	deleted_count = 0
	failed_count = 0
	for variant in variants_to_delete:
		try:
			variant.delete()
			deleted_count += 1
		except Exception:
			failed_count += 1

	if deleted_count:
		messages.success(request, f'{deleted_count} variant(s) deleted successfully.')
	if failed_count:
		messages.warning(request, f'{failed_count} variant(s) could not be deleted due to existing references.')

	return redirect('assets_list')


@login_required
def assets_item_types_list(request):
	can_view_categories = (
		request.user.is_superuser
		or request.user.has_perm('core.view_assettrackercategory')
		or request.user.has_perm('core.view_assetitemtype')
	)
	if not can_view_categories:
		return _permission_denied_response(request, 'You do not have permission to perform this action.')

	query = (request.GET.get('q') or '').strip()
	item_types = AssetItemType.objects.order_by('name')
	if query:
		item_types = item_types.filter(Q(name__icontains=query) | Q(code__icontains=query) | Q(prefix__icontains=query))

	page = Paginator(item_types, 20).get_page(request.GET.get('page'))
	return render(request, 'core/assets_item_types_list.html', {'item_types_page': page, 'query': query})


@login_required
def assets_item_type_create(request):
	restricted_response = _require_permission(request, 'core.add_assetitemtype')
	if restricted_response:
		return restricted_response

	if request.method == 'POST':
		form = AssetItemTypeForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request, 'Item type created successfully.')
			return redirect('assets_item_types_list')
	else:
		form = AssetItemTypeForm()

	return render(
		request,
		'core/assets_item_type_form.html',
		{'form': form, 'page_title': 'Create Item Type', 'submit_label': 'Save Type'},
	)


@login_required
def assets_item_type_update(request, item_type_id):
	restricted_response = _require_permission(request, 'core.change_assetitemtype')
	if restricted_response:
		return restricted_response

	item_type = get_object_or_404(AssetItemType, pk=item_type_id)
	if request.method == 'POST':
		form = AssetItemTypeForm(request.POST, instance=item_type)
		if form.is_valid():
			form.save()
			messages.success(request, 'Item type updated successfully.')
			return redirect('assets_item_types_list')
	else:
		form = AssetItemTypeForm(instance=item_type)

	return render(
		request,
		'core/assets_item_type_form.html',
		{'form': form, 'page_title': f'Edit Item Type: {item_type.name}', 'submit_label': 'Save Changes'},
	)


@login_required
def assets_item_type_delete(request, item_type_id):
	restricted_response = _require_permission(request, 'core.delete_assetitemtype')
	if restricted_response:
		return restricted_response

	item_type = get_object_or_404(AssetItemType, pk=item_type_id)
	if request.method == 'POST':
		in_use = AssetItem.objects.filter(item_type=item_type.code).exists()
		if in_use:
			messages.error(request, 'This item type is currently used by existing assets and cannot be deleted.')
			return redirect('assets_item_types_list')

		item_type.delete()
		messages.success(request, 'Item type deleted successfully.')
		return redirect('assets_item_types_list')

	return render(request, 'core/assets_item_type_confirm_delete.html', {'item_type': item_type})


@login_required
@require_POST
def assets_item_types_bulk_delete(request):
	restricted_response = _require_permission(request, 'core.delete_assetitemtype')
	if restricted_response:
		return restricted_response

	item_type_ids = request.POST.getlist('item_type_ids')
	if not item_type_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			item_type_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in item_type_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No item types selected for deletion.')
		return redirect('assets_item_types_list')

	item_types_to_delete = AssetItemType.objects.filter(pk__in=parsed_ids)
	deleted_count = 0
	in_use_count = 0
	failed_count = 0

	for item_type in item_types_to_delete:
		if AssetItem.objects.filter(item_type=item_type.code).exists():
			in_use_count += 1
			continue
		try:
			item_type.delete()
			deleted_count += 1
		except Exception:
			failed_count += 1

	if deleted_count:
		messages.success(request, f'{deleted_count} item type(s) deleted successfully.')
	if in_use_count:
		messages.warning(
			request,
			f'{in_use_count} item type(s) are in use by assets and could not be deleted.',
		)
	if failed_count:
		messages.warning(request, f'{failed_count} item type(s) could not be deleted due to existing references.')

	return redirect('assets_item_types_list')


@login_required
@require_POST
def assets_generate_tags(request):
	restricted_response = _require_permission(request, 'core.add_assettagbatch')
	if restricted_response:
		return restricted_response

	department_id = (request.POST.get('department') or '').strip()
	department = None
	items = (
		AssetItem.objects.select_related('department', 'parent_item')
		.filter(is_active=True)
		.annotate(variant_count=Count('variants'))
		.filter(Q(parent_item__isnull=False) | Q(variant_count=0))
	)
	if department_id:
		department = get_object_or_404(AssetDepartment, pk=department_id)
		items = items.filter(department=department)

	items = items.order_by('item_code', 'id')
	if not items.exists():
		messages.warning(request, 'No active assets found to generate a tag document.')
		return redirect('assets_list')

	batch = AssetTagBatch.objects.create(
		department=department,
		generated_by=request.user,
		notes='Generated from Asset Tracker',
	)

	entries = []
	for item in items:
		parent_code = item.parent_item.item_code if item.parent_item else ''
		entries.append(
			AssetTagEntry(
				batch=batch,
				item=item,
				tag_code=item.item_code,
				item_code_snapshot=item.item_code,
				item_name_snapshot=item.item_name,
				specification_snapshot=item.specification or '',
				department_name_snapshot=item.department.name,
				parent_item_code_snapshot=parent_code,
				sequence=1,
			)
		)

	AssetTagEntry.objects.bulk_create(entries)
	messages.success(
		request,
		f'Asset tagging document generated. Batch #{batch.id} has {len(entries)} registered item ID tag(s).',
	)
	return redirect('assets_tag_document', batch_id=batch.id)


@login_required
def assets_tag_document(request, batch_id):
	restricted_response = _require_permission(request, 'core.view_assettagbatch')
	if restricted_response:
		return restricted_response

	batch = get_object_or_404(
		AssetTagBatch.objects.select_related('department', 'generated_by', 'generated_by__profile').prefetch_related('entries'),
		pk=batch_id,
	)

	entries = batch.entries.all()
	generator_profile = getattr(batch.generated_by, 'profile', None) if batch.generated_by else None
	context = {
		'batch': batch,
		'generator_profile': generator_profile,
		'entries': entries,
		'total_tags': entries.count(),
		'unique_item_codes_count': entries.values('item_code_snapshot').distinct().count(),
	}
	return render(request, 'core/assets_tag_document.html', context)


@login_required
@require_POST
def assets_tag_batch_delete(request, batch_id):
	restricted_response = _require_permission(request, 'core.delete_assettagbatch')
	if restricted_response:
		return restricted_response

	batch = get_object_or_404(AssetTagBatch, pk=batch_id)
	batch.delete()
	messages.success(request, f'Tag batch #{batch_id} deleted successfully.')
	return redirect('assets_list')


@login_required
@require_POST
def assets_tag_batches_bulk_delete(request):
	restricted_response = _require_permission(request, 'core.delete_assettagbatch')
	if restricted_response:
		return restricted_response

	batch_ids = request.POST.getlist('batch_ids')
	if not batch_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			batch_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in batch_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No generated tag documents selected.')
		return redirect('assets_list')

	batches = AssetTagBatch.objects.filter(pk__in=parsed_ids)
	count = batches.count()
	batches.delete()

	if count:
		messages.success(request, f'{count} generated tag document(s) deleted successfully.')
	else:
		messages.warning(request, 'No matching generated tag documents found.')

	return redirect('assets_list')


@login_required
def roles_list(request):
	restricted_response = _require_permission(request, 'auth.view_group')
	if restricted_response:
		return restricted_response

	query = (request.GET.get('q') or '').strip()
	roles = Group.objects.prefetch_related('permissions', 'user_set', 'user_set__profile').order_by('name')
	if query:
		roles = roles.filter(name__icontains=query)

	roles = list(roles)
	role_member_profiles_map = {}
	role_permissions_grouped_map = {}
	for role in roles:
		for member in role.user_set.all():
			if member.id not in role_member_profiles_map:
				role_member_profiles_map[member.id] = getattr(member, 'profile', None)
		role_permissions_grouped_map[role.id] = build_permission_preview_groups(role.permissions.all())

	return render(
		request,
		'core/roles_list.html',
		{
			'roles': roles,
			'query': query,
			'role_member_profiles_map': role_member_profiles_map,
			'role_permissions_grouped_map': role_permissions_grouped_map,
		},
	)


@login_required
def roles_create(request):
	restricted_response = _require_permission(request, 'auth.add_group')
	if restricted_response:
		return restricted_response

	if request.method == 'POST':
		form = RoleForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request, 'Role created successfully.')
			return redirect('roles_list')
	else:
		form = RoleForm()

	return render(
		request,
		'core/roles_form.html',
		{
			'form': form,
			'page_title': 'Create Role',
			'submit_label': 'Create Role',
		},
	)


@login_required
def roles_update(request, role_id):
	restricted_response = _require_permission(request, 'auth.change_group')
	if restricted_response:
		return restricted_response

	role = get_object_or_404(Group, pk=role_id)

	if request.method == 'POST':
		form = RoleForm(request.POST, instance=role)
		if form.is_valid():
			form.save()
			messages.success(request, 'Role updated successfully.')
			return redirect('roles_list')
	else:
		form = RoleForm(instance=role)

	return render(
		request,
		'core/roles_form.html',
		{
			'form': form,
			'page_title': f'Edit Role: {role.name}',
			'submit_label': 'Save Changes',
		},
	)


@login_required
def roles_delete(request, role_id):
	restricted_response = _require_permission(request, 'auth.delete_group')
	if restricted_response:
		return restricted_response

	role = get_object_or_404(Group, pk=role_id)
	if request.method == 'POST':
		role.delete()
		messages.success(request, 'Role deleted successfully.')
		return redirect('roles_list')

	return render(request, 'core/roles_confirm_delete.html', {'role': role})


@login_required
def otp_setup(request):
	device, _ = TOTPDevice.objects.get_or_create(user=request.user, name='default', defaults={'confirmed': False})
	is_modal = request.GET.get('modal') == '1' or request.POST.get('modal') == '1'
	qr_url = (
		'https://chart.googleapis.com/chart?cht=qr&chs=220x220&chl='
		f"{quote(device.config_url, safe='')}"
	)
	qr_svg = ''
	if qrcode and SvgImage:
		try:
			qr_img = qrcode.make(device.config_url, image_factory=SvgImage, box_size=8, border=2)
			buffer = BytesIO()
			qr_img.save(buffer)
			qr_svg = buffer.getvalue().decode('utf-8')
		except Exception:
			qr_svg = ''

	if request.method == 'POST':
		token = request.POST.get('token', '').strip()
		if device.verify_token(token):
			device.confirmed = True
			device.save(update_fields=['confirmed'])
			messages.success(request, 'Two-factor authentication has been enabled.')
			if is_modal:
				return JsonResponse({'ok': True, 'message': 'Two-factor authentication has been enabled.'})
			return redirect('dashboard')
		messages.error(request, 'Invalid authenticator code. Try again.')
		if is_modal:
			return JsonResponse({'ok': False, 'message': 'Invalid authenticator code. Try again.'}, status=400)

	template_name = 'registration/partials/otp_setup_modal.html' if is_modal else 'registration/otp_setup.html'
	return render(request, template_name, {'device': device, 'qr_url': qr_url, 'qr_svg': qr_svg})


@login_required
def send_email_verification(request):
	is_modal = request.GET.get('modal') == '1' or request.POST.get('modal') == '1'
	profile, _ = UserProfile.objects.get_or_create(user=request.user)
	if profile.email_verified:
		messages.info(request, 'Your email is already verified.')
		if is_modal:
			return render(request, 'registration/partials/email_verified_success_modal.html')
		return redirect('dashboard')

	if request.method == 'POST':
		form = EmailVerificationRequestForm(request.POST)
		if form.is_valid():
			email = form.cleaned_data['email']
			if email.lower() != request.user.email.lower():
				form.add_error('email', 'Please enter the email currently linked to your account.')
				if is_modal:
					return JsonResponse({'ok': False, 'message': 'Please enter the email currently linked to your account.'}, status=400)
			else:
				_send_email_verification_code(request, request.user)
				request.session['email_verification_pending'] = request.user.pk
				if is_modal:
					otp_html = render_to_string(
						'registration/partials/email_verification_otp_modal.html',
						{
							'form': EmailVerificationOTPForm(),
							'resend_seconds_remaining': EMAIL_VERIFICATION_RESEND_COOLDOWN,
						},
						request=request,
					)
					return JsonResponse({
						'ok': True,
						'message': 'Verification code sent. Please check your inbox.',
						'html': otp_html,
						'title': 'Verify Email',
					})
				messages.success(request, 'Verification code sent. Please check your inbox.')
				return redirect('email_verification_otp')
		elif is_modal:
			message = 'Please correct the email and try again.'
			if form.errors:
				first_field = next(iter(form.errors))
				message = form.errors[first_field][0]
			return JsonResponse({'ok': False, 'message': message}, status=400)
	else:
		form = EmailVerificationRequestForm(initial={'email': request.user.email})

	template_name = 'registration/partials/send_verification_modal.html' if is_modal else 'registration/send_verification.html'
	status_code = 400 if is_modal and request.method == 'POST' and form.errors else 200
	return render(request, template_name, {'form': form}, status=status_code)


@login_required
def email_verification_otp(request):
	is_modal = request.GET.get('modal') == '1' or request.POST.get('modal') == '1'
	profile, _ = UserProfile.objects.get_or_create(user=request.user)
	if profile.email_verified:
		messages.info(request, 'Your email is already verified.')
		if is_modal:
			return render(request, 'registration/partials/email_verified_success_modal.html')
		return redirect('dashboard')

	if request.session.get('email_verification_pending') != request.user.pk and not cache.get(_email_verification_code_key(request.user.pk)):
		messages.info(request, 'Request a verification code first.')
		return redirect('send_email_verification')

	code_key = _email_verification_code_key(request.user.pk)
	remaining_seconds = _get_email_verification_resend_remaining(request.user)
	code_exists = cache.get(code_key) is not None

	if request.method == 'POST':
		action = (request.POST.get('action') or 'verify').strip().lower()
		if action == 'resend':
			if remaining_seconds > 0:
				form = EmailVerificationOTPForm()
				form.add_error(None, f'Please wait {remaining_seconds} second(s) before resending.')
			else:
				_send_email_verification_code(request, request.user)
				request.session['email_verification_pending'] = request.user.pk
				if is_modal:
					otp_html = render_to_string(
						'registration/partials/email_verification_otp_modal.html',
						{
							'form': EmailVerificationOTPForm(),
							'resend_seconds_remaining': EMAIL_VERIFICATION_RESEND_COOLDOWN,
						},
						request=request,
					)
					return JsonResponse({
						'ok': True,
						'message': 'Verification code resent. Please check your inbox.',
						'html': otp_html,
						'title': 'Verify Email',
					})
				messages.success(request, 'Verification code resent. Please check your inbox.')
				return redirect('email_verification_otp')
		else:
			form = EmailVerificationOTPForm(request.POST)
			if form.is_valid():
				submitted_code = form.cleaned_data['otp']
				stored_code = cache.get(code_key)
				if not stored_code:
					form.add_error('otp', 'Your verification code expired. Please resend it.')
				elif submitted_code != stored_code:
					form.add_error('otp', 'Invalid verification code. Please try again.')
				else:
					profile.email_verified = True
					profile.save(update_fields=['email_verified'])
					create_notification(
						request.user,
						title='Email verified',
						message='Email verified na. Your account email is now confirmed.',
						link_url=reverse('dashboard'),
					)
					cache.delete(code_key)
					cache.delete(_email_verification_sent_at_key(request.user.pk))
					request.session.pop('email_verification_pending', None)
					if is_modal:
						return render(request, 'registration/partials/email_verified_success_modal.html')
					messages.success(request, 'Email verified successfully. You can now sign in securely.')
					return redirect('dashboard')
				if is_modal:
					return render(request, 'registration/partials/email_verification_otp_modal.html', {'form': form, 'resend_seconds_remaining': remaining_seconds}, status=400)
	else:
		form = EmailVerificationOTPForm()

	if not code_exists:
		messages.info(request, 'Request a new verification code if your previous one expired.')

	context = {
		'form': form,
		'resend_seconds_remaining': remaining_seconds,
	}
	if is_modal:
		return render(request, 'registration/partials/email_verification_otp_modal.html', context)
	return render(request, 'registration/email_verification_otp.html', context)


def verify_email(request, token):
	verification_token = get_object_or_404(EmailVerificationToken, token=token)
	if not verification_token.is_valid:
		messages.error(request, 'Verification link is invalid or expired.')
		return redirect('login')

	profile, _ = UserProfile.objects.get_or_create(user=verification_token.user)
	profile.email_verified = True
	profile.save(update_fields=['email_verified'])
	create_notification(
		verification_token.user,
		title='Email verified',
		message='Email verified na. Your account email is now confirmed.',
		link_url=reverse('dashboard'),
	)
	verification_token.mark_used()

	messages.success(request, 'Email verified successfully. You can now sign in securely.')
	return redirect('login')


@login_required
def mark_notifications_read(request):
	if request.method != 'POST':
		return redirect(request.META.get('HTTP_REFERER', reverse('dashboard')))

	# Check if a specific notification ID is provided (AJAX request)
	notification_id = request.POST.get('notification_id')
	if notification_id:
		try:
			notification = Notification.objects.get(id=notification_id, user=request.user)
			notification.delete()
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'status': 'success'})
		except Notification.DoesNotExist:
			if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
				return JsonResponse({'status': 'error', 'message': 'Notification not found'}, status=404)
	else:
		# Remove all unread notifications from the dropdown list.
		Notification.objects.filter(user=request.user, is_read=False).delete()
	
	return redirect(request.META.get('HTTP_REFERER', reverse('dashboard')))


@login_required
def notifications_feed(request):
	"""Return latest unread notifications for live dropdown refresh."""
	notifications_qs = Notification.objects.filter(user=request.user, is_read=False).order_by('-created_at')
	notifications = [
		{
			'id': notification.id,
			'title': notification.title,
			'message': notification.message,
			'link_url': notification.link_url or '#',
		}
		for notification in notifications_qs[:5]
	]

	return JsonResponse(
		{
			'ok': True,
			'notifications': notifications,
			'unread_notification_count': notifications_qs.count(),
		}
	)


@login_required
def notifications_list(request):
	"""Show notifications page with pagination and basic filters."""
	query = (request.GET.get('q') or '').strip()
	status_filter = (request.GET.get('status') or 'all').strip().lower()

	notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
	if query:
		notifications = notifications.filter(
			Q(title__icontains=query)
			| Q(message__icontains=query)
		)

	if status_filter == 'unread':
		notifications = notifications.filter(is_read=False)
	elif status_filter == 'read':
		notifications = notifications.filter(is_read=True)
	else:
		status_filter = 'all'

	page_obj = Paginator(notifications, 20).get_page(request.GET.get('page'))

	context = {
		'page_obj': page_obj,
		'query': query,
		'status_filter': status_filter,
		'total_notifications': Notification.objects.filter(user=request.user).count(),
		'total_unread': Notification.objects.filter(user=request.user, is_read=False).count(),
	}
	return render(request, 'core/notifications_list.html', context)


@login_required
def update_user_status(request):
	"""Update user status and render modal or JSON response"""
	is_modal = request.GET.get('modal') == '1' or request.POST.get('modal') == '1'
	
	if request.method == 'POST':
		form = UserStatusForm(request.POST, instance=request.user.profile)
		if form.is_valid():
			profile = form.save()
			_sync_presence_session(request, profile.status)
			if is_modal:
				return render(request, 'registration/partials/user_status_modal.html', {
					'form': UserStatusForm(instance=request.user.profile),
					'status_updated': True
				})
			else:
				messages.success(request, 'Status updated successfully.')
				return redirect('profile_page')
	else:
		form = UserStatusForm(instance=request.user.profile)
	
	if is_modal:
		return render(request, 'registration/partials/user_status_modal.html', {'form': form})
	
	return redirect('profile_page')


@login_required
@require_POST
def update_presence_status(request):
	status = (request.POST.get('status') or '').strip().lower()
	allowed_statuses = {'active', 'idle', 'offline'}
	if status not in allowed_statuses:
		return JsonResponse({'ok': False, 'message': 'Invalid status value.'}, status=400)

	client_session_id = (request.POST.get('session_id') or '').strip()
	if not request.session.get('presence_session_id'):
		request.session['presence_session_id'] = client_session_id or secrets.token_hex(16)

	server_session_id = request.session.get('presence_session_id')
	if client_session_id and client_session_id != server_session_id:
		return JsonResponse({'ok': False, 'message': 'Invalid session context.'}, status=403)

	event_ms_raw = (request.POST.get('event_ms') or '').strip()
	try:
		event_ms = int(event_ms_raw) if event_ms_raw else int(timezone.now().timestamp() * 1000)
	except ValueError:
		event_ms = int(timezone.now().timestamp() * 1000)

	last_event_ms = int(request.session.get('presence_last_event_ms') or 0)
	if event_ms < last_event_ms:
		return JsonResponse({'ok': True, 'ignored': True, 'status': request.session.get('presence_status', status)})

	_set_user_status(request.user, status)
	_sync_presence_session(request, status, event_ms=event_ms)
	return JsonResponse({'ok': True, 'status': status, 'session_id': request.session.get('presence_session_id')})


class SecurePasswordResetView(PasswordResetView):
	template_name = 'registration/password_reset_form.html'
	email_template_name = 'registration/password_reset_email.txt'
	subject_template_name = 'registration/password_reset_subject.txt'
	success_url = reverse_lazy('password_reset_done')


class SecurePasswordResetConfirmView(PasswordResetConfirmView):
	template_name = 'registration/password_reset_confirm.html'
	success_url = reverse_lazy('password_reset_complete')


class SecurePasswordChangeView(PasswordChangeView):
	template_name = 'registration/password_change_form.html'
	success_url = reverse_lazy('login')
	form_class = SecurePasswordChangeForm

	def get_template_names(self):
		if self.request.GET.get('modal') == '1' or self.request.POST.get('modal') == '1':
			return ['registration/partials/password_change_modal.html']
		return [self.template_name]

	def form_valid(self, form):
		user = form.save()
		invalidate_user_sessions(user)
		logout(self.request)
		self.request.session.flush()
		messages.success(self.request, 'Password changed. Please sign in again.')
		if self.request.GET.get('modal') == '1' or self.request.POST.get('modal') == '1':
			return JsonResponse(
				{
					'ok': True,
					'message': 'Password changed. Please sign in again.',
					'redirect_url': str(self.success_url),
				}
			)
		return redirect(self.success_url)

	def form_invalid(self, form):
		if self.request.GET.get('modal') == '1' or self.request.POST.get('modal') == '1':
			return render(
				self.request,
				'registration/partials/password_change_modal.html',
				{'form': form},
				status=400,
			)
		return super().form_invalid(form)


class EmailVerificationSentView(TemplateView):
	template_name = 'registration/email_verification_sent.html'


def _get_accountability_report_queryset(request):
	"""Build accountability queryset based on month or explicit date range."""
	month_value = (request.GET.get('month') or '').strip()
	start_date_raw = (request.GET.get('start_date') or '').strip()
	end_date_raw = (request.GET.get('end_date') or '').strip()

	queryset = _filter_accountability_by_visibility(
		request,
		AssetAccountability.objects.select_related('item', 'borrowed_by').filter(request_status='approved'),
	).order_by('-date_borrowed')
	report_scope_label = 'All Dates'
	resolved_month = ''
	resolved_start_date = ''
	resolved_end_date = ''

	if month_value:
		try:
			year_str, month_str = month_value.split('-', 1)
			year_int = int(year_str)
			month_int = int(month_str)
			if 1 <= month_int <= 12:
				queryset = queryset.filter(date_borrowed__year=year_int, date_borrowed__month=month_int)
				resolved_month = month_value
				report_scope_label = timezone.datetime(year_int, month_int, 1).strftime('%B %Y')
		except (ValueError, TypeError):
			pass
	else:
		start_date = parse_date(start_date_raw) if start_date_raw else None
		end_date = parse_date(end_date_raw) if end_date_raw else None
		if start_date:
			queryset = queryset.filter(date_borrowed__date__gte=start_date)
			resolved_start_date = start_date.isoformat()
		if end_date:
			queryset = queryset.filter(date_borrowed__date__lte=end_date)
			resolved_end_date = end_date.isoformat()

		if start_date and end_date:
			report_scope_label = f'{start_date:%Y-%m-%d} to {end_date:%Y-%m-%d}'
		elif start_date:
			report_scope_label = f'From {start_date:%Y-%m-%d}'
		elif end_date:
			report_scope_label = f'Up to {end_date:%Y-%m-%d}'

	filter_state = {
		'month': resolved_month,
		'start_date': resolved_start_date,
		'end_date': resolved_end_date,
	}
	return queryset, report_scope_label, filter_state


def _can_review_accountability_requests(user):
	return user.is_superuser or user.has_perm('core.change_assetaccountability')


def _ensure_active_accountability_template():
	if AssetAccountabilityTemplate.objects.filter(is_active=True).exists():
		return
	fallback_template = AssetAccountabilityTemplate.objects.order_by('-updated_at', '-created_at').first()
	if fallback_template:
		fallback_template.is_active = True
		fallback_template.save(update_fields=['is_active', 'updated_at'])


def _can_manage_accountability_templates(user):
	return user.is_superuser or user.has_perm('core.change_assetaccountability')


def _build_accountability_line_item_context(accountability):
	item_name = accountability.item.item_name or ''
	specifications = accountability.item.specification or ''
	return {
		'item_id': accountability.item.item_code or '',
		'brand_model_item_name': item_name,
		'brand_model': item_name,
		'item_name': item_name,
		'specifications': specifications,
		'specification': specifications,
		'asset_type': accountability.item.get_item_type_display(),
		'quantity': str(accountability.quantity_borrowed or 0),
	}


def _get_accountability_template_line_records(accountability):
	if not accountability.batch_id:
		return [accountability]
	return list(
		AssetAccountability.objects
		.select_related('item', 'item__department', 'borrowed_by', 'borrowed_by__profile')
		.filter(batch_id=accountability.batch_id)
		.order_by('created_at', 'id')
	)


def _build_accountability_template_placeholders(accountability):
	user = accountability.borrowed_by
	profile = getattr(user, 'profile', None) if user else None
	name = accountability.accountable_name or ((user.get_full_name() or user.username) if user else '')
	department = accountability.department or getattr(profile, 'department', '') or getattr(accountability.item.department, 'name', '') or ''
	position = accountability.position_role or getattr(profile, 'position', '') or getattr(profile, 'role', '') or ''
	contact_number = accountability.contact_number or getattr(profile, 'contact_number', '') or getattr(profile, 'phone_number', '') or ''
	line_records = _get_accountability_template_line_records(accountability)
	line_items = [_build_accountability_line_item_context(record) for record in line_records]
	first_line_item = line_items[0] if line_items else _build_accountability_line_item_context(accountability)
	placeholders = {
		'{{ name }}': name,
		'{{ department }}': department,
		'{{ position_role }}': position,
		'{{ position }}': position,
		'{{ role }}': position,
		'{{ contact_number }}': contact_number,
		'{{ control_number }}': accountability.control_number or '',
		'{{ item_id }}': first_line_item['item_id'],
		'{{ brand_model_item_name }}': first_line_item['brand_model_item_name'],
		'{{ brand_model }}': first_line_item['brand_model'],
		'{{ item_name }}': first_line_item['item_name'],
		'{{ specifications }}': first_line_item['specifications'],
		'{{ specification }}': first_line_item['specification'],
		'{{ asset_type }}': first_line_item['asset_type'],
		'{{ quantity }}': first_line_item['quantity'],
		'{{ date_borrowed }}': timezone.localtime(accountability.date_borrowed).strftime('%B %d, %Y') if accountability.date_borrowed else '',
		'{{ status }}': accountability.status.title() if accountability.status else '',
		'{{ notes }}': accountability.notes or '',
	}

	for index, line_item in enumerate(line_items, start=1):
		placeholders[f'{{{{ item_{index}_id }}}}'] = line_item['item_id']
		placeholders[f'{{{{ item_{index}_brand_model }}}}'] = line_item['brand_model']
		placeholders[f'{{{{ item_{index}_brand_model_item_name }}}}'] = line_item['brand_model_item_name']
		placeholders[f'{{{{ item_{index}_name }}}}'] = line_item['item_name']
		placeholders[f'{{{{ item_{index}_specification }}}}'] = line_item['specification']
		placeholders[f'{{{{ item_{index}_specifications }}}}'] = line_item['specifications']
		placeholders[f'{{{{ item_{index}_asset_type }}}}'] = line_item['asset_type']
		placeholders[f'{{{{ item_{index}_quantity }}}}'] = line_item['quantity']

	for index in range(len(line_items) + 1, 51):
		placeholders[f'{{{{ item_{index}_id }}}}'] = ''
		placeholders[f'{{{{ item_{index}_brand_model }}}}'] = ''
		placeholders[f'{{{{ item_{index}_brand_model_item_name }}}}'] = ''
		placeholders[f'{{{{ item_{index}_name }}}}'] = ''
		placeholders[f'{{{{ item_{index}_specification }}}}'] = ''
		placeholders[f'{{{{ item_{index}_specifications }}}}'] = ''
		placeholders[f'{{{{ item_{index}_asset_type }}}}'] = ''
		placeholders[f'{{{{ item_{index}_quantity }}}}'] = ''

	placeholders['{{ line_items }}'] = '\n'.join(
		f"{line_item['item_id']} | {line_item['brand_model_item_name']} | "
		f"{line_item['specifications']} | {line_item['asset_type']} | {line_item['quantity']}"
		for line_item in line_items
	)
	placeholders['{{ line_items_table }}'] = placeholders['{{ line_items }}']
	return placeholders, line_items


def _build_accountability_template_placeholder_guide():
	return [
		{'placeholder': '{{ name }}', 'description': 'Full name of the accountable person.', 'use_case': 'Use beside Name or Employee Name.'},
		{'placeholder': '{{ department }}', 'description': 'Department value available to the system.', 'use_case': 'Use beside Department.'},
		{'placeholder': '{{ position_role }}', 'description': 'Position or role value available to the system.', 'use_case': 'Use beside Position/Role.'},
		{'placeholder': '{{ contact_number }}', 'description': 'Contact number value available to the system.', 'use_case': 'Use beside Contact Number.'},
		{'placeholder': '{{ control_number }}', 'description': 'Auto-generated accountability control number.', 'use_case': 'Use in the control number/header area.'},
		{'placeholder': '{{ item_id }}', 'description': 'Asset item ID or code.', 'use_case': 'Use in a fixed Item ID table cell.'},
		{'placeholder': '{{ brand_model }}', 'description': 'Brand/model or item name from the asset record.', 'use_case': 'Use in the Brand/Model column.'},
		{'placeholder': '{{ brand_model_item_name }}', 'description': 'Brand/model/item name from the asset record.', 'use_case': 'Use in the Brand/Model/Item Name column.'},
		{'placeholder': '{{ specifications }}', 'description': 'Asset specifications.', 'use_case': 'Use in the Specifications column.'},
		{'placeholder': '{{ asset_type }}', 'description': 'Asset type display label.', 'use_case': 'Use in the Asset Type column.'},
		{'placeholder': '{{ quantity }}', 'description': 'Borrowed quantity.', 'use_case': 'Use in the Quantity column.'},
		{'placeholder': '{{ item_1_id }}', 'description': 'Fixed-row placeholder for row 1 item ID. Use `item_2_...`, `item_3_...`, and so on for more rows.', 'use_case': 'Use in spreadsheets with pre-made table rows.'},
		{'placeholder': '{{ item_1_brand_model }}', 'description': 'Fixed-row placeholder for row 1 brand/model.', 'use_case': 'Use in the Brand/Model column for fixed-row templates.'},
		{'placeholder': '{{ item_1_specification }}', 'description': 'Fixed-row placeholder for row 1 specification.', 'use_case': 'Use in the Specification column for fixed-row templates.'},
		{'placeholder': '{{ item_1_asset_type }}', 'description': 'Fixed-row placeholder for row 1 asset type.', 'use_case': 'Use in the Asset Type column for fixed-row templates.'},
		{'placeholder': '{{ item_1_quantity }}', 'description': 'Fixed-row placeholder for row 1 quantity.', 'use_case': 'Use in the Quantity column for fixed-row templates.'},
		{'placeholder': '{{#line_items}} ... {{/line_items}}', 'description': 'Dynamic repeating block for `.docx` and `.xlsx` templates.', 'use_case': 'Use around the accountability item table row.'},
	]


def _build_accountability_template_file_payload(accountability):
	template_record = AssetAccountabilityTemplate.objects.filter(is_active=True).order_by('-updated_at', '-created_at').first()
	if not template_record:
		return None

	extension = _fund_request_template_extension(template_record)
	placeholders, line_items = _build_accountability_template_placeholders(accountability)
	output_name = f'asset-accountability-{accountability.control_number or accountability.pk}{extension}'
	rendered_template = _render_fund_request_template_binary_from_template(template_record, placeholders, line_items, output_name)
	if rendered_template:
		pdf_bytes = _convert_office_bytes_to_pdf(
			rendered_template['content'],
			rendered_template['filename'],
			allow_structured_preview_fallback=False,
		)
		if pdf_bytes:
			return {
				'content': pdf_bytes,
				'content_type': 'application/pdf',
				'filename': f'{Path(rendered_template["filename"]).stem}.pdf',
				'template_record': template_record,
				'extension': '.pdf',
				'source': 'template_generated_pdf',
			}

	if extension == '.pdf':
		with template_record.file.open('rb') as template_file:
			return {
				'content': template_file.read(),
				'content_type': 'application/pdf',
				'filename': f'asset-accountability-{accountability.control_number or accountability.pk}.pdf',
				'template_record': template_record,
				'extension': extension,
				'source': 'template_pdf',
			}
	if extension in {'.doc', '.xls'}:
		with template_record.file.open('rb') as template_file:
			pdf_bytes = _convert_office_bytes_to_pdf(
				template_file.read(),
				Path(template_record.file.name).name,
				allow_structured_preview_fallback=False,
			)
		if pdf_bytes:
			return {
				'content': pdf_bytes,
				'content_type': 'application/pdf',
				'filename': f'asset-accountability-{accountability.control_number or accountability.pk}.pdf',
				'template_record': template_record,
				'extension': '.pdf',
				'source': 'template_converted_pdf',
			}
	return None


def _filter_accountability_by_visibility(request, queryset):
	"""Limit accountability visibility to own records for non-reviewers."""
	if _can_review_accountability_requests(request.user):
		return queryset
	return queryset.filter(borrowed_by=request.user)


@login_required
def accountability_report_summary(request):
	"""Generate summary report document for accountability records."""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	queryset, report_scope_label, filter_state = _get_accountability_report_queryset(request)
	summary = queryset.aggregate(
		total_records=Count('id'),
		total_quantity=Sum('quantity_borrowed'),
		active_borrowed=Count('id', filter=Q(status='borrowed')),
		total_returned=Count('id', filter=Q(status='returned')),
	)
	unique_borrowers_count = queryset.filter(borrowed_by__isnull=False).values('borrowed_by').distinct().count()

	item_summary_rows = (
		queryset
		.values('item__item_code', 'item__item_name')
		.annotate(total_records=Count('id'), total_quantity=Sum('quantity_borrowed'))
		.order_by('-total_quantity', '-total_records', 'item__item_code')[:20]
	)

	borrower_summary_rows = (
		queryset
		.values('borrowed_by__username', 'borrowed_by__first_name', 'borrowed_by__last_name')
		.annotate(total_records=Count('id'), total_quantity=Sum('quantity_borrowed'))
		.order_by('-total_quantity', '-total_records', 'borrowed_by__username')[:20]
	)

	context = {
		'summary': summary,
		'unique_borrowers_count': unique_borrowers_count,
		'item_summary_rows': item_summary_rows,
		'borrower_summary_rows': borrower_summary_rows,
		'report_scope_label': report_scope_label,
		'generated_at': timezone.localtime(timezone.now()),
		'filter_state': filter_state,
		'auto_print': (request.GET.get('auto_print') or '').strip() == '1',
	}
	return render(request, 'core/accountability_report_summary.html', context)


@login_required
def accountability_report_list(request):
	"""Generate detailed accountability list report document."""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	queryset, report_scope_label, filter_state = _get_accountability_report_queryset(request)
	list_page = Paginator(queryset, 20).get_page(request.GET.get('list_page'))

	for row in list_page:
		row.item_stock_status = row.item.get_stock_status()

	context = {
		'list_page': list_page,
		'report_scope_label': report_scope_label,
		'generated_at': timezone.localtime(timezone.now()),
		'filter_state': filter_state,
		'auto_print': (request.GET.get('auto_print') or '').strip() == '1',
	}
	return render(request, 'core/accountability_report_list.html', context)


@login_required
def accountability_report_summary_csv(request):
	"""Download summary report as CSV document."""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	queryset, report_scope_label, _ = _get_accountability_report_queryset(request)
	summary = queryset.aggregate(
		total_records=Count('id'),
		total_quantity=Sum('quantity_borrowed'),
		active_borrowed=Count('id', filter=Q(status='borrowed')),
		total_returned=Count('id', filter=Q(status='returned')),
	)
	unique_borrowers_count = queryset.filter(borrowed_by__isnull=False).values('borrowed_by').distinct().count()

	item_summary_rows = (
		queryset
		.values('item__item_code', 'item__item_name')
		.annotate(total_records=Count('id'), total_quantity=Sum('quantity_borrowed'))
		.order_by('-total_quantity', '-total_records', 'item__item_code')[:20]
	)

	borrower_summary_rows = (
		queryset
		.values('borrowed_by__username', 'borrowed_by__first_name', 'borrowed_by__last_name')
		.annotate(total_records=Count('id'), total_quantity=Sum('quantity_borrowed'))
		.order_by('-total_quantity', '-total_records', 'borrowed_by__username')[:20]
	)

	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="asset_accountability_summary_report.csv"'
	writer = csv.writer(response)
	writer.writerow(['Asset Accountability Summary Report'])
	writer.writerow(['Scope', report_scope_label])
	writer.writerow(['Generated At', timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M')])
	writer.writerow([])

	writer.writerow(['Summary Metrics'])
	writer.writerow(['Total Records', summary.get('total_records') or 0])
	writer.writerow(['Total Quantity', summary.get('total_quantity') or 0])
	writer.writerow(['Active Borrowed', summary.get('active_borrowed') or 0])
	writer.writerow(['Returned', summary.get('total_returned') or 0])
	writer.writerow(['Unique Borrowers', unique_borrowers_count])
	writer.writerow([])

	writer.writerow(['Top Borrowed Items'])
	writer.writerow(['Item Code', 'Item Name', 'Total Records', 'Total Quantity'])
	for row in item_summary_rows:
		writer.writerow([
			row.get('item__item_code') or '-',
			row.get('item__item_name') or '-',
			row.get('total_records') or 0,
			row.get('total_quantity') or 0,
		])
	writer.writerow([])

	writer.writerow(['Top Borrowers'])
	writer.writerow(['Borrower', 'Total Records', 'Total Quantity'])
	for row in borrower_summary_rows:
		full_name = f"{(row.get('borrowed_by__first_name') or '').strip()} {(row.get('borrowed_by__last_name') or '').strip()}".strip()
		writer.writerow([
			full_name or row.get('borrowed_by__username') or '-',
			row.get('total_records') or 0,
			row.get('total_quantity') or 0,
		])

	return response


@login_required
def accountability_report_list_csv(request):
	"""Download detailed accountability list report as CSV document."""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	queryset, report_scope_label, _ = _get_accountability_report_queryset(request)
	response = HttpResponse(content_type='text/csv')
	response['Content-Disposition'] = 'attachment; filename="asset_accountability_detailed_report.csv"'
	writer = csv.writer(response)
	writer.writerow(['Asset Accountability Detailed Report'])
	writer.writerow(['Scope', report_scope_label])
	writer.writerow(['Generated At', timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M')])
	writer.writerow([])
	writer.writerow([
		'Item Code',
		'Item Name',
		'Borrowed By',
		'Quantity',
		'Borrowed Date',
		'Status',
		'Stock Status',
		'Department',
		'Notes',
	])

	for row in queryset:
		borrower_name = '-'
		if row.borrowed_by:
			borrower_name = row.borrowed_by.get_full_name() or row.borrowed_by.username
		writer.writerow([
			row.item.item_code,
			row.item.item_name,
			borrower_name,
			row.quantity_borrowed,
			timezone.localtime(row.date_borrowed).strftime('%Y-%m-%d %H:%M') if row.date_borrowed else '-',
			row.status,
			row.item.get_stock_status(),
			row.item.department.name,
			row.notes or '-',
		])

	return response


@login_required
def accountability_document_download(request, accountability_id):
	"""Download an accountability document from the active uploaded template."""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	accountability = get_object_or_404(
		_filter_accountability_by_visibility(
			request,
			AssetAccountability.objects.select_related('item', 'item__department', 'borrowed_by', 'borrowed_by__profile'),
		),
		pk=accountability_id,
	)
	payload = _build_accountability_template_file_payload(accountability)
	if not payload:
		messages.warning(
			request,
			'Unable to generate the accountability PDF. Upload an active PDF, DOCX, XLSX, DOC, or XLS template and make sure a server-side converter is available.',
		)
		return redirect('accountability_list')

	response = HttpResponse(payload['content'], content_type=payload['content_type'])
	response['Content-Disposition'] = f'attachment; filename="{payload["filename"]}"'
	return response


@login_required
def accountability_list(request):
	"""View accountability records (items borrowed)"""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	can_manage_templates = _can_manage_accountability_templates(request.user)
	template_form = AssetAccountabilityTemplateForm()
	if request.method == 'POST' and can_manage_templates:
		template_action = (request.POST.get('template_action') or '').strip()
		if template_action == 'upload':
			template_form = AssetAccountabilityTemplateForm(request.POST, request.FILES)
			if template_form.is_valid():
				template_record = template_form.save(commit=False)
				template_record.uploaded_by = request.user
				template_record.save()
				messages.success(request, f'Accountability template "{template_record.name}" uploaded.')
				return redirect('accountability_list')
		elif template_action.startswith('set_default:'):
			template_id = template_action.split(':', 1)[1]
			template_record = get_object_or_404(AssetAccountabilityTemplate, pk=int(template_id))
			AssetAccountabilityTemplate.objects.exclude(pk=template_record.pk).update(is_active=False)
			template_record.is_active = True
			template_record.save(update_fields=['is_active', 'updated_at'])
			messages.success(request, f'"{template_record.name}" is now the active accountability template.')
			return redirect('accountability_list')
		elif template_action.startswith('delete:'):
			template_id = template_action.split(':', 1)[1]
			template_record = get_object_or_404(AssetAccountabilityTemplate, pk=int(template_id))
			template_name = template_record.name
			template_record.delete()
			_ensure_active_accountability_template()
			messages.success(request, f'Accountability template "{template_name}" deleted.')
			return redirect('accountability_list')

	query = (request.GET.get('q') or '').strip()
	status_filter = (request.GET.get('status') or '').strip()
	can_review_requests = _can_review_accountability_requests(request.user)
	active_template = AssetAccountabilityTemplate.objects.filter(is_active=True).order_by('-updated_at', '-created_at').first()
	all_templates = AssetAccountabilityTemplate.objects.select_related('uploaded_by').order_by('-is_active', '-updated_at', '-created_at')

	records = (
		_filter_accountability_by_visibility(
			request,
			AssetAccountability.objects
		.select_related('item', 'item__department', 'borrowed_by', 'borrowed_by__profile')
		.prefetch_related('return_proofs')
		.filter(request_status='approved')
		)
		.order_by('-date_borrowed')
	)
	pending_requests = _filter_accountability_by_visibility(
		request,
		AssetAccountability.objects.select_related('item', 'item__department', 'borrowed_by', 'borrowed_by__profile').filter(request_status='pending'),
	).order_by('-created_at')

	if query:
		records = records.filter(
			Q(item__item_code__icontains=query)
			| Q(item__item_name__icontains=query)
			| Q(borrowed_by__first_name__icontains=query)
			| Q(borrowed_by__last_name__icontains=query)
			| Q(borrowed_by__username__icontains=query)
		)
		pending_requests = pending_requests.filter(
			Q(item__item_code__icontains=query)
			| Q(item__item_name__icontains=query)
			| Q(borrowed_by__first_name__icontains=query)
			| Q(borrowed_by__last_name__icontains=query)
			| Q(borrowed_by__username__icontains=query)
		)

	if status_filter and status_filter in ['borrowed', 'returned']:
		records = records.filter(status=status_filter)

	# Add stock status to items
	for record in records:
		record.item_stock_status = record.item.get_stock_status()

	for request_entry in pending_requests:
		request_entry.item_stock_status = request_entry.item.get_stock_status()

	records_page = Paginator(records, 20).get_page(request.GET.get('page'))
	pending_requests_page = Paginator(pending_requests, 20).get_page(request.GET.get('pending_page'))
	borrower_ids = [
		row.borrowed_by_id
		for row in list(records_page.object_list) + list(pending_requests_page.object_list)
		if row.borrowed_by_id
	]
	borrower_profiles_map = {
		profile.user_id: profile
		for profile in UserProfile.objects.filter(user_id__in=borrower_ids)
	}
	return_proofs_map = {}
	for record in records_page.object_list:
		proof_entries = []
		for proof in record.return_proofs.all():
			if not proof.image:
				continue
			proof_entries.append(
				{
					'url': proof.image.url,
					'name': (proof.image.name or '').split('/')[-1] or 'Return proof image',
					'size': proof.image.size,
				}
			)
		return_proofs_map[str(record.id)] = proof_entries

	context = {
		'records_page': records_page,
		'pending_requests_page': pending_requests_page,
		'borrower_profiles_map': borrower_profiles_map,
		'return_proofs_map': return_proofs_map,
		'can_review_requests': can_review_requests,
		'can_manage_approved_records': request.user.is_superuser or request.user.has_perm('core.change_assetaccountability') or request.user.has_perm('core.delete_assetaccountability'),
		'can_manage_templates': can_manage_templates,
		'template_form': template_form,
		'active_template': active_template,
		'all_templates': all_templates,
		'accountability_placeholder_guide': _build_accountability_template_placeholder_guide(),
		'query': query,
		'status_filter': status_filter,
		'total_pending_requests': _filter_accountability_by_visibility(request, AssetAccountability.objects.filter(request_status='pending')).count(),
		'total_borrowed_active': _filter_accountability_by_visibility(request, AssetAccountability.objects.filter(request_status='approved', status='borrowed')).count(),
		'total_returned': _filter_accountability_by_visibility(request, AssetAccountability.objects.filter(request_status='approved', status='returned')).count(),
	}
	return render(request, 'core/accountability_list.html', context)


@login_required
def accountability_create(request):
	"""Create new accountability record (borrow item)"""
	restricted_response = _require_permission(request, 'core.add_assetaccountability')
	if restricted_response:
		return restricted_response

	if request.method == 'POST':
		form = AssetAccountabilityForm(request.POST)
		if form.is_valid():
			selected_items = list(form.cleaned_data.get('items') or [])
			item_quantities_map = form.cleaned_data.get('item_quantities_map') or {}
			notes = form.cleaned_data.get('notes') or ''
			accountability_details = {
				'accountable_name': form.cleaned_data.get('accountable_name') or '',
				'department': form.cleaned_data.get('department') or '',
				'position_role': form.cleaned_data.get('position_role') or '',
				'contact_number': form.cleaned_data.get('contact_number') or '',
			}

			created_requests = []
			batch_id = uuid.uuid4()
			for selected_item in selected_items:
				selected_quantity = int(item_quantities_map.get(selected_item.pk, 1))
				accountability = AssetAccountability.objects.create(
					item=selected_item,
					batch_id=batch_id,
					borrowed_by=request.user,
					quantity_borrowed=selected_quantity,
					notes=notes,
					request_status='pending',
					status='borrowed',
					**accountability_details,
				)
				created_requests.append(accountability)
				_notify_accountability_reviewers(accountability)

			if len(created_requests) == 1:
				messages.success(
					request,
					f'Borrow request for "{created_requests[0].item.item_code}" submitted. Waiting for admin approval.',
				)
			else:
				messages.success(
					request,
					f'{len(created_requests)} borrow requests submitted. Waiting for admin approval.',
				)
			return redirect('accountability_list')
	else:
		profile = getattr(request.user, 'profile', None)
		form = AssetAccountabilityForm(initial={
			'accountable_name': request.user.get_full_name() or request.user.username,
			'department': getattr(profile, 'department', '') or '',
			'position_role': getattr(profile, 'position', '') or getattr(profile, 'role', '') or '',
			'contact_number': getattr(profile, 'contact_number', '') or getattr(profile, 'phone_number', '') or '',
		})

	context = {
		'form': form,
		'page_title': 'Borrow Item',
		'submit_label': 'Submit Request',
	}
	return render(request, 'core/accountability_form.html', context)


def _get_accountability_reviewers():
	"""Return active users who can review asset borrow requests."""
	return User.objects.filter(is_active=True).filter(
		Q(is_superuser=True) | Q(user_permissions__codename='change_assetaccountability') | Q(groups__permissions__codename='change_assetaccountability')
	).distinct()


def _send_accountability_email(users, subject, message_lines):
	"""Send plain-text email notifications for accountability events."""
	recipient_list = sorted({(user.email or '').strip() for user in users if (user.email or '').strip()})
	if not recipient_list:
		return

	try:
		send_mail(
			subject=subject,
			message='\n'.join(message_lines),
			from_email=settings.DEFAULT_FROM_EMAIL,
			recipient_list=recipient_list,
			fail_silently=True,
		)
	except Exception:
		# In-app notifications still work even if SMTP is not configured.
		pass


def _notify_accountability_reviewers(accountability):
	borrower_name = accountability.borrowed_by.get_full_name() or accountability.borrowed_by.username
	link_url = reverse('accountability_list')
	reviewers = []
	for reviewer in _get_accountability_reviewers():
		if reviewer.pk == accountability.borrowed_by_id:
			continue
		reviewers.append(reviewer)
		create_notification(
			user=reviewer,
			title='New Borrow Request',
			message=(
				f'{borrower_name} requested {accountability.quantity_borrowed}x of '
				f'{accountability.item.item_code} - {accountability.item.item_name}.'
			),
			link_url=link_url,
		)

	_send_accountability_email(
		reviewers,
		subject=f'[Avantech] New Borrow Request: {accountability.item.item_code}',
		message_lines=[
			'New asset borrow request submitted.',
			f'Borrower: {borrower_name}',
			f'Item: {accountability.item.item_code} - {accountability.item.item_name}',
			f'Quantity: {accountability.quantity_borrowed}',
			f'Notes: {accountability.notes or "-"}',
			'Please review in Asset Accountability page.',
		],
	)


def _notify_accountability_requester(accountability):
	if not accountability.borrowed_by:
		return

	title = 'Borrow Request Approved' if accountability.request_status == 'approved' else 'Borrow Request Declined'
	if accountability.request_status == 'approved':
		message = (
			f'Your request for {accountability.quantity_borrowed}x of {accountability.item.item_code} '
			f'was approved.'
		)
	else:
		reason_suffix = f' Reason: {accountability.decision_reason}' if accountability.decision_reason else ''
		message = (
			f'Your request for {accountability.quantity_borrowed}x of {accountability.item.item_code} '
			f'was declined.{reason_suffix}'
		)

	create_notification(
		user=accountability.borrowed_by,
		title=title,
		message=message,
		link_url=reverse('accountability_list'),
	)

	processor_name = '-'
	if accountability.processed_by:
		processor_name = accountability.processed_by.get_full_name() or accountability.processed_by.username

	_send_accountability_email(
		[accountability.borrowed_by],
		subject=f'[Avantech] {title}: {accountability.item.item_code}',
		message_lines=[
			title,
			f'Item: {accountability.item.item_code} - {accountability.item.item_name}',
			f'Quantity: {accountability.quantity_borrowed}',
			f'Decision By: {processor_name}',
			f'Reason: {accountability.decision_reason or "-"}',
			'You can view the latest status in Asset Accountability page.',
		],
	)


@login_required
@require_POST
def accountability_decide(request, accountability_id):
	"""Approve or decline pending accountability requests."""
	restricted_response = _require_permission(request, 'core.change_assetaccountability')
	if restricted_response:
		return restricted_response

	decision = (request.POST.get('decision') or '').strip().lower()
	reason = (request.POST.get('reason') or '').strip()
	if decision not in {'approve', 'decline'}:
		messages.error(request, 'Invalid decision action.')
		return redirect('accountability_list')

	if decision == 'decline' and not reason:
		messages.error(request, 'Reason is required when declining a borrow request.')
		return redirect('accountability_list')

	accountability = get_object_or_404(AssetAccountability.objects.select_related('item', 'borrowed_by'), pk=accountability_id)
	if accountability.request_status != 'pending':
		messages.info(request, 'This request has already been reviewed.')
		return redirect('accountability_list')

	for attempt in range(3):
		try:
			with transaction.atomic():
				accountability = AssetAccountability.objects.select_related('item', 'borrowed_by').get(pk=accountability_id)
				if accountability.request_status != 'pending':
					messages.info(request, 'This request has already been reviewed.')
					return redirect('accountability_list')

				if decision == 'approve':
					available_total = accountability.item.get_total_stock_quantity()
					if accountability.quantity_borrowed > available_total:
						messages.error(
							request,
							f'Cannot approve request. Available stock for {accountability.item.item_code} is {available_total}.',
						)
						return redirect('accountability_list')
					accountability.mark_approved(processed_by=request.user, reason=reason)
					status_now = accountability.item.get_stock_status()
					message_text = f'Request approved for {accountability.item.item_code}.'
				else:
					accountability.mark_declined(processed_by=request.user, reason=reason)
					status_now = None
					message_text = f'Request declined for {accountability.item.item_code}.'

			break
		except OperationalError as exc:
			if 'database is locked' not in str(exc).lower():
				raise
			if attempt == 2:
				messages.error(request, 'The database is busy right now. Please try again in a moment.')
				return redirect('accountability_list')

	if decision == 'approve' and status_now in ['low stock', 'out of stock']:
		_send_stock_alert_notification(accountability.item, status_now)
	messages.success(request, message_text)
	_notify_accountability_requester(accountability)
	return redirect('accountability_list')


@login_required
def accountability_item_auto_fill(request):
	"""AJAX endpoint to auto-fill item details when item ID is selected"""
	if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
		return JsonResponse({'ok': False, 'message': 'Invalid request'}, status=400)

	item_id = request.GET.get('item_id', '')
	if not item_id:
		return JsonResponse({'ok': False, 'message': 'Item ID required'}, status=400)

	try:
		item = AssetItem.objects.get(pk=item_id)
	except AssetItem.DoesNotExist:
		return JsonResponse({'ok': False, 'message': 'Item not found'}, status=404)

	available_stock = int(item.get_total_stock_quantity() or 0)
	if item.get_stock_status() == 'out of stock' or available_stock < 1:
		return JsonResponse({'ok': False, 'message': 'This item is out of stock and cannot be borrowed.'}, status=409)
	if int(item.stock_quantity or 0) < 1:
		return JsonResponse({'ok': False, 'message': 'This item has zero stock and cannot be borrowed.'}, status=409)

	return JsonResponse({
		'ok': True,
		'item_name': item.item_name,
		'item_type': item.get_item_type_display(),
		'available_stock': available_stock,
		'stock_status': item.get_stock_status(),
		'specification': item.specification,
		'image_url': item.get_primary_image_url(),
	})


@login_required
def accountability_return(request, accountability_id):
	"""Mark a borrowed item as returned and restore stock"""
	if request.method != 'POST':
		return JsonResponse({'ok': False, 'message': 'POST required'}, status=405)

	restricted_response = _require_permission(request, 'core.change_assetaccountability')
	if restricted_response:
		return restricted_response

	accountability = get_object_or_404(AssetAccountability, pk=accountability_id)
	if accountability.request_status != 'approved':
		messages.error(request, 'Only approved borrow records can be returned.')
		return redirect('accountability_list')

	if accountability.status == 'returned':
		messages.info(request, 'This item is already marked as returned.')
		return redirect('accountability_list')

	proof_uploads = [upload for upload in request.FILES.getlist('return_proof_images') if upload]
	with transaction.atomic():
		accountability = AssetAccountability.objects.select_related('item', 'borrowed_by').get(pk=accountability_id)
		if not accountability.mark_returned():
			messages.info(request, 'This item is already marked as returned.')
			return redirect('accountability_list')

		for upload in proof_uploads:
			AssetReturnProof.objects.create(
				accountability=accountability,
				image=upload,
				uploaded_by=request.user,
			)

	proof_count = len(proof_uploads)
	if proof_count:
		messages.success(
			request,
			f'Item "{accountability.item.item_code}" marked as returned with {proof_count} proof image(s). Stock restored ({accountability.quantity_borrowed}x).',
		)
	else:
		messages.success(request, f'Item "{accountability.item.item_code}" marked as returned. Stock restored ({accountability.quantity_borrowed}x).')

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		return JsonResponse({'ok': True, 'message': 'Item returned successfully.'})

	return redirect('accountability_list')


@login_required
@require_POST
def accountability_pending_bulk_decide(request):
	"""Bulk approve/decline pending borrow requests."""
	restricted_response = _require_permission(request, 'core.change_assetaccountability')
	if restricted_response:
		return restricted_response

	decision = (request.POST.get('decision') or '').strip().lower()
	reason = (request.POST.get('reason') or '').strip()
	if decision not in {'approve', 'decline'}:
		messages.error(request, 'Invalid bulk decision action.')
		return redirect('accountability_list')

	if decision == 'decline' and not reason:
		messages.error(request, 'Reason is required for bulk decline.')
		return redirect('accountability_list')

	request_ids = request.POST.getlist('request_ids')
	if not request_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			request_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in request_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No pending requests selected.')
		return redirect('accountability_list')

	entries = list(
		AssetAccountability.objects.select_related('item', 'borrowed_by').filter(pk__in=parsed_ids, request_status='pending')
	)
	processed_count = 0
	skipped_count = 0

	for entry in entries:
		locked_out = False
		for attempt in range(3):
			try:
				with transaction.atomic():
					entry = AssetAccountability.objects.select_related('item', 'borrowed_by').get(pk=entry.pk)
					if entry.request_status != 'pending':
						locked_out = True
						break
					if decision == 'approve':
						available_total = entry.item.get_total_stock_quantity()
						if entry.quantity_borrowed > available_total:
							skipped_count += 1
							locked_out = True
							break
						entry.mark_approved(processed_by=request.user, reason=reason)
						status_now = entry.item.get_stock_status()
					else:
						entry.mark_declined(processed_by=request.user, reason=reason)
						status_now = None
				break
			except OperationalError as exc:
				if 'database is locked' not in str(exc).lower():
					raise
				if attempt == 2:
					messages.error(request, 'The database is busy right now. Please try again in a moment.')
					return redirect('accountability_list')
		if locked_out and decision == 'approve':
			continue

		if decision == 'approve' and status_now in ['low stock', 'out of stock']:
			_send_stock_alert_notification(entry.item, status_now)

		_notify_accountability_requester(entry)
		processed_count += 1

	if processed_count:
		messages.success(request, f'{processed_count} pending request(s) processed.')
	if skipped_count:
		messages.warning(request, f'{skipped_count} request(s) skipped due to insufficient stock.')

	return redirect('accountability_list')


@login_required
@require_POST
def accountability_records_bulk_action(request):
	"""Bulk action on approved borrow records (return/delete)."""
	action = (request.POST.get('action') or '').strip().lower()
	if action not in {'return', 'delete'}:
		messages.error(request, 'Invalid bulk action for approved records.')
		return redirect('accountability_list')

	if action == 'delete':
		restricted_response = _require_permission(request, 'core.delete_assetaccountability')
	else:
		restricted_response = _require_permission(request, 'core.change_assetaccountability')
	if restricted_response:
		return restricted_response

	record_ids = request.POST.getlist('record_ids')
	if not record_ids:
		raw_selected_ids = (request.POST.get('selected_ids') or '').strip()
		if raw_selected_ids:
			record_ids = [segment.strip() for segment in raw_selected_ids.split(',') if segment.strip()]

	parsed_ids = []
	for raw_id in record_ids:
		value = (raw_id or '').strip()
		if value.isdigit():
			parsed_ids.append(int(value))

	if not parsed_ids:
		messages.warning(request, 'No approved records selected.')
		return redirect('accountability_list')

	entries = list(AssetAccountability.objects.select_related('item').filter(pk__in=parsed_ids, request_status='approved'))
	processed_count = 0
	skipped_count = 0

	if action == 'return':
		for entry in entries:
			if entry.status != 'borrowed':
				skipped_count += 1
				continue
			entry.mark_returned()
			processed_count += 1
		messages.success(request, f'{processed_count} approved record(s) marked as returned.')
		if skipped_count:
			messages.info(request, f'{skipped_count} selected record(s) were already returned.')
		return redirect('accountability_list')

	for entry in entries:
		if entry.status == 'borrowed':
			entry.mark_returned()
		entry.delete()
		processed_count += 1

	messages.success(request, f'{processed_count} approved record(s) deleted successfully.')
	return redirect('accountability_list')


def _send_stock_alert_notification(item, stock_status):
	"""Send notification to users with asset tracker access when stock is low or out"""
	try:
		# Get users with permission to manage assets
		from django.contrib.auth.models import Permission
		from django.contrib.contenttypes.models import ContentType

		content_type = ContentType.objects.get_for_model(AssetItem)
		perm = Permission.objects.get(content_type=content_type, codename='view_assetitem')

		# Notify all users with this permission
		for user_group in perm.group_set.all():
			for user in user_group.user_set.all():
				title = f'Stock Alert: {item.item_code}'
				message = f'Item "{item.item_name}" is now {stock_status}. Current total stock: {item.get_total_stock_quantity()}'
				Notification.objects.create(user=user, title=title, message=message)
	except Exception as e:
		# Silently fail if notification creation fails
		pass
