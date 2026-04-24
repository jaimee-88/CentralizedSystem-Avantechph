from datetime import timedelta
import csv
from io import BytesIO
from json import dumps
import secrets
from urllib.parse import quote

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group, User
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView, PasswordResetView
from django.core.cache import cache
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import transaction
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
from django.utils.dateparse import parse_date
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.http import urlencode
from django.views import View
from django.views.generic import FormView, TemplateView
from django.views.decorators.http import require_POST
from axes.models import AccessAttempt, AccessFailureLog
from axes.utils import reset as axes_reset
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

try:
	import qrcode
	from qrcode.image.svg import SvgImage
except Exception:
	qrcode = None
	SvgImage = None

from .auth_utils import invalidate_user_sessions
from .forms import (
	AssetAccountabilityForm,
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
	LoginEvent,
	Notification,
	PatchNote,
	PatchNoteAttachment,
	PatchNoteComment,
	PatchNoteReaction,
	UserProfile,
)
from .notifications import create_notification


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
				f"{permission.content_type.app_label}: {permission.name}"
				for permission in managed_user.user_permissions.all()
			}
		)
		group_permission_names = sorted(
			{
				f"{permission.content_type.app_label}: {permission.name}"
				for group in managed_user.groups.all()
				for permission in group.permissions.all()
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
		sorted_permissions = sorted(
			role.permissions.all(),
			key=lambda permission: (permission.content_type.app_label, permission.name),
		)
		grouped_permissions = {}
		for permission in sorted_permissions:
			app_label_key = permission.content_type.app_label
			if app_label_key not in grouped_permissions:
				grouped_permissions[app_label_key] = {
					'app_label': app_label_key.replace('_', ' ').title(),
					'items': [],
				}
			grouped_permissions[app_label_key]['items'].append(permission.name)
		role_permissions_grouped_map[str(role.id)] = list(grouped_permissions.values())

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
		sorted_permissions = sorted(
			role.permissions.all(),
			key=lambda permission: (permission.content_type.app_label, permission.name),
		)
		grouped_permissions = {}
		for permission in sorted_permissions:
			app_label_key = permission.content_type.app_label
			if app_label_key not in grouped_permissions:
				grouped_permissions[app_label_key] = {
					'app_label': app_label_key.replace('_', ' ').title(),
					'items': [],
				}
			grouped_permissions[app_label_key]['items'].append(permission.name)
		role_permissions_grouped_map[str(role.id)] = list(grouped_permissions.values())

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
	items = AssetItem.objects.select_related('department', 'parent_item').filter(is_active=True)
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

		sorted_permissions = sorted(
			role.permissions.all(),
			key=lambda permission: (permission.content_type.app_label, permission.name),
		)
		grouped_permissions = {}
		for permission in sorted_permissions:
			app_label_key = permission.content_type.app_label
			if app_label_key not in grouped_permissions:
				grouped_permissions[app_label_key] = {
					'app_label': app_label_key.replace('_', ' ').title(),
					'items': [],
				}
			grouped_permissions[app_label_key]['items'].append(permission.name)

		role_permissions_grouped_map[role.id] = list(grouped_permissions.values())

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
def accountability_list(request):
	"""View accountability records (items borrowed)"""
	restricted_response = _require_permission(request, 'core.view_assetaccountability')
	if restricted_response:
		return restricted_response

	query = (request.GET.get('q') or '').strip()
	status_filter = (request.GET.get('status') or '').strip()
	can_review_requests = _can_review_accountability_requests(request.user)

	records = (
		_filter_accountability_by_visibility(
			request,
			AssetAccountability.objects
		.select_related('item', 'borrowed_by', 'borrowed_by__profile')
		.prefetch_related('return_proofs')
		.filter(request_status='approved')
		)
		.order_by('-date_borrowed')
	)
	pending_requests = _filter_accountability_by_visibility(
		request,
		AssetAccountability.objects.select_related('item', 'borrowed_by', 'borrowed_by__profile').filter(request_status='pending'),
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

			created_requests = []
			for selected_item in selected_items:
				selected_quantity = int(item_quantities_map.get(selected_item.pk, 1))
				accountability = AssetAccountability.objects.create(
					item=selected_item,
					borrowed_by=request.user,
					quantity_borrowed=selected_quantity,
					notes=notes,
					request_status='pending',
					status='borrowed',
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
		form = AssetAccountabilityForm()

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
