import uuid
import re
import base64
import hashlib
from pathlib import Path

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.db import models
from django.db.models import Q, Sum
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.text import slugify

try:
	from cryptography.fernet import Fernet, InvalidToken
except Exception:
	Fernet = None
	InvalidToken = Exception


def client_quotation_upload_to(instance, filename):
	original_name = filename or 'quotation.pdf'
	extension = Path(original_name).suffix.lower() or '.pdf'
	client = getattr(instance, 'client', None)
	quotation = getattr(instance, 'quotation', None)
	if client is None and quotation is not None:
		client = getattr(quotation, 'client', None)

	client_slug = slugify(getattr(client, 'full_name', '') or 'client')
	version_source = getattr(instance, 'version', None)
	if version_source is None and quotation is not None:
		version_source = getattr(quotation, 'version', 0)
	version = int(version_source or 0)
	date_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d')
	formatted_name = f'{client_slug}_v{version:03d}_{date_stamp}{extension}'
	return f'client_quotations/{formatted_name}'


def client_lead_proof_upload_to(instance, filename):
	original_name = filename or 'lead-proof.jpg'
	extension = Path(original_name).suffix.lower() or '.jpg'
	client_slug = slugify(getattr(instance, 'full_name', '') or 'client')
	date_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d')
	formatted_name = f'{client_slug}_lead_proof_{date_stamp}{extension}'
	return f'client_lead_proofs/{formatted_name}'


def accountability_return_proof_upload_to(instance, filename):
	original_name = filename or 'return-proof.jpg'
	extension = Path(original_name).suffix.lower() or '.jpg'
	accountability_id = getattr(instance, 'accountability_id', None) or 'accountability'
	date_stamp = timezone.localtime(timezone.now()).strftime('%Y%m%d')
	formatted_name = f'{accountability_id}_return_proof_{date_stamp}{extension}'
	return f'accountability_return_proofs/{formatted_name}'


def _credentials_fernet():
	fernet_cls = Fernet
	if fernet_cls is None:
		# Retry import at call time so a live server can recover after package install.
		try:
			from cryptography.fernet import Fernet as fernet_cls
		except Exception as exc:
			raise ValidationError('Credential encryption backend is not available. Install cryptography to continue.') from exc
	digest = hashlib.sha256((settings.SECRET_KEY or '').encode('utf-8')).digest()
	return fernet_cls(base64.urlsafe_b64encode(digest))


class UserProfile(models.Model):
	STATUS_CHOICES = [
		('active', 'Active'),
		('offline', 'Offline'),
		('idle', 'Idle'),
	]

	user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
	email_verified = models.BooleanField(default=False)
	status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
	branch = models.CharField(max_length=120, blank=True, default='')
	avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
	last_login_ip = models.GenericIPAddressField(blank=True, null=True)
	last_login_user_agent = models.CharField(max_length=255, blank=True)

	def __str__(self):
		return f'Profile<{self.user.username}>'

	def get_status_color(self):
		"""Get the color for the status badge"""
		status_colors = {
			'active': '#198754',  # Green
			'offline': '#dc3545',  # Red
			'idle': '#ffc107',  # Yellow
		}
		return status_colors.get(self.status, '#198754')


class LoginEvent(models.Model):
	user = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		blank=True,
		null=True,
		related_name='login_events',
	)
	username_attempt = models.CharField(max_length=150)
	ip_address = models.GenericIPAddressField(blank=True, null=True)
	user_agent = models.CharField(max_length=255, blank=True)
	successful = models.BooleanField(default=False)
	reason = models.CharField(max_length=64, default='unknown')
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'LoginEvent<{self.username_attempt}:{self.reason}>'


class EmailVerificationToken(models.Model):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='email_tokens')
	token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
	created_at = models.DateTimeField(auto_now_add=True)
	expires_at = models.DateTimeField()
	used_at = models.DateTimeField(blank=True, null=True)

	class Meta:
		ordering = ['-created_at']

	@property
	def is_valid(self):
		return self.used_at is None and timezone.now() < self.expires_at

	def mark_used(self):
		self.used_at = timezone.now()
		self.save(update_fields=['used_at'])

	def __str__(self):
		return f'EmailToken<{self.user.username}:{self.token}>'


class Notification(models.Model):
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
	title = models.CharField(max_length=120)
	message = models.CharField(max_length=255)
	link_url = models.CharField(max_length=255, blank=True)
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	read_at = models.DateTimeField(blank=True, null=True)

	class Meta:
		ordering = ['-created_at']

	def mark_read(self):
		if not self.is_read:
			self.is_read = True
			self.read_at = timezone.now()
			self.save(update_fields=['is_read', 'read_at'])

	def __str__(self):
		return f'Notification<{self.user.username}:{self.title}>'


class Client(models.Model):
	CLIENT_TYPE_CHOICES = [
		('new', 'New Client'),
		('old', 'Old Client'),
	]

	USAGE_CHOICES = [
		('daytime', 'Daytime'),
		('night', 'Night'),
		('both', 'Both'),
	]

	PROPERTY_STATUS_CHOICES = [
		('under_construction', 'Under Construction'),
		('built', 'Built'),
	]

	STATUS_CHOICES = [
		('inquiry', 'Inquiry'),
		('quotation_sent', 'Quotation Sent'),
		('negotiation', 'Negotiation'),
		('closed_won', 'Closed Won'),
		('closed_lost', 'Closed Lost'),
	]

	LEAD_STATUS_CHOICES = [
		('intake', 'Intake'),
		('converted', 'Converted'),
		('lost', 'Lost'),
		('qualified', 'Qualified'),
		('not_qualified', 'Not Qualified'),
	]

	full_name = models.CharField(max_length=150)
	exact_address = models.TextField()
	active_phone_number = models.CharField(max_length=32)
	email = models.EmailField()
	average_monthly_electricity_bill = models.DecimalField(max_digits=12, decimal_places=2)
	usage_of_electricity = models.CharField(max_length=20, choices=USAGE_CHOICES)
	appliances_and_electric_things = models.TextField()
	property_status = models.CharField(max_length=24, choices=PROPERTY_STATUS_CHOICES)
	client_type = models.CharField(max_length=8, choices=CLIENT_TYPE_CHOICES, default='new')
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inquiry')
	lead_status = models.CharField(max_length=20, choices=LEAD_STATUS_CHOICES, default='intake')
	lead_disposition_reason = models.TextField(blank=True)
	lead_proof_image = models.FileField(upload_to=client_lead_proof_upload_to, blank=True, null=True)
	handled_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='handled_clients',
	)
	handled_date = models.DateField(default=timezone.localdate)
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='created_clients',
	)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'Client<{self.full_name}:{self.status}>'


class ClientDeletionRequest(models.Model):
	STATUS_CHOICES = [
		('pending', 'Pending'),
		('approved', 'Approved'),
		('rejected', 'Rejected'),
	]

	client = models.ForeignKey(
		Client,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='deletion_requests',
	)
	client_name_snapshot = models.CharField(max_length=150)
	reason = models.TextField(blank=True)
	requested_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='client_deletion_requests_created',
	)
	requested_at = models.DateTimeField(auto_now_add=True)
	resubmission_count = models.PositiveIntegerField(default=0)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
	reviewed_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='client_deletion_requests_reviewed',
	)
	reviewed_at = models.DateTimeField(blank=True, null=True)
	review_notes = models.TextField(blank=True)

	class Meta:
		ordering = ['-requested_at']
		permissions = [
			('approve_clientdeletionrequest', 'Can approve client deletion requests'),
		]

	def __str__(self):
		return f'ClientDeletionRequest<{self.client_name_snapshot}:{self.status}>'


class ClientQuotation(models.Model):
	NEGOTIATION_STATUS_CHOICES = [
		('sent', 'Sent'),
		('under_negotiation', 'Under Negotiation'),
		('accepted', 'Accepted'),
		('rejected', 'Rejected'),
	]

	client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='quotations')
	version = models.PositiveIntegerField()
	product_package = models.CharField(max_length=150, default='')
	quoted_amount = models.DecimalField(max_digits=12, decimal_places=2)
	quotation_notes = models.TextField(blank=True)
	scanned_document = models.FileField(upload_to=client_quotation_upload_to, blank=True, null=True)
	negotiation_status = models.CharField(max_length=20, choices=NEGOTIATION_STATUS_CHOICES, default='sent')
	sent_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='client_quotations_sent',
	)
	sent_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-sent_at']
		constraints = [
			models.UniqueConstraint(fields=['client', 'version'], name='unique_client_quotation_version'),
		]

	def __str__(self):
		return f'ClientQuotation<{self.client.full_name}:v{self.version}>'


class ClientQuotationDocument(models.Model):
	quotation = models.ForeignKey(ClientQuotation, on_delete=models.CASCADE, related_name='documents')
	file = models.FileField(upload_to=client_quotation_upload_to)
	uploaded_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='client_quotation_documents_uploaded',
	)
	uploaded_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-uploaded_at']

	def __str__(self):
		return f'ClientQuotationDocument<{self.quotation_id}:{self.file.name}>'


class AssetDepartment(models.Model):
	name = models.CharField(max_length=100, unique=True)
	is_default = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['name']

	def __str__(self):
		return self.name


class AssetItemType(models.Model):
	name = models.CharField(max_length=80, unique=True)
	code = models.SlugField(max_length=30, unique=True)
	prefix = models.CharField(max_length=5, default='AST')
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['name']
		permissions = [
			('view_assettrackercategory', 'Can view asset tracker category'),
		]

	def __str__(self):
		return self.name

	def clean(self):
		self.code = (self.code or '').strip().lower()
		self.prefix = (self.prefix or 'AST').strip().upper()
		if len(self.prefix) < 2 or len(self.prefix) > 5 or not self.prefix.isalnum():
			raise ValidationError({'prefix': 'Prefix must be 2-5 alphanumeric characters.'})


class AssetItem(models.Model):
	TYPE_PREFIX_FALLBACK_MAP = {
		'cable': 'CBL',
		'laptop': 'LP',
		'other': 'AST',
	}

	department = models.ForeignKey(AssetDepartment, on_delete=models.PROTECT, related_name='assets')
	parent_item = models.ForeignKey('self', on_delete=models.PROTECT, null=True, blank=True, related_name='variants')
	item_name = models.CharField(max_length=150)
	item_type = models.CharField(max_length=30, default='other', db_index=True)
	item_code = models.CharField(max_length=20, unique=True, blank=True)
	code_prefix = models.CharField(max_length=5, blank=True)
	specification = models.CharField(max_length=255, blank=True)
	note = models.TextField(blank=True)
	asset_image = models.ImageField(upload_to='asset_images/', blank=True, null=True)
	stock_quantity = models.PositiveIntegerField(default=0)
	low_stock_threshold = models.PositiveIntegerField(default=5, help_text='Alert when stock falls below this level')
	is_active = models.BooleanField(default=True)
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='assets_created',
	)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['item_code', 'item_name']

	def __str__(self):
		return f'{self.item_code} - {self.item_name}'

	def clean(self):
		if self.parent_item:
			if self.parent_item_id == self.id:
				raise ValidationError({'parent_item': 'Parent item cannot be the same as the item.'})
			if self.parent_item.department_id != self.department_id:
				raise ValidationError({'parent_item': 'Variant must belong to the same department as its parent item.'})

	def _determine_prefix(self):
		if self.code_prefix:
			return self.code_prefix.upper()
		if self.parent_item and self.parent_item.code_prefix:
			return self.parent_item.code_prefix.upper()

		item_type_code = (self.item_type or '').strip().lower()
		type_prefix = (
			AssetItemType.objects
			.filter(code=item_type_code)
			.values_list('prefix', flat=True)
			.first()
		)
		if type_prefix:
			return str(type_prefix).upper()
		return self.TYPE_PREFIX_FALLBACK_MAP.get(item_type_code, 'AST')

	def _next_item_code(self, prefix):
		pattern = re.compile(rf'^{re.escape(prefix)}(\d+)$')
		max_value = 2599
		for code in AssetItem.objects.filter(item_code__startswith=prefix).values_list('item_code', flat=True):
			match = pattern.match(code or '')
			if not match:
				continue
			max_value = max(max_value, int(match.group(1)))
		return f'{prefix}{max_value + 1}'

	def save(self, *args, **kwargs):
		self.item_type = (self.item_type or 'other').strip().lower()
		self.code_prefix = self._determine_prefix()
		if not self.item_code:
			self.item_code = self._next_item_code(self.code_prefix)
		super().save(*args, **kwargs)

	def get_item_type_display(self):
		label = (
			AssetItemType.objects
			.filter(code=(self.item_type or '').strip().lower())
			.values_list('name', flat=True)
			.first()
		)
		if label:
			return label
		raw = (self.item_type or '').strip()
		if not raw:
			return 'Other'
		return raw.replace('-', ' ').replace('_', ' ').title()

	def get_primary_image_url(self):
		prefetched = getattr(self, '_prefetched_objects_cache', {})
		prefetched_images = prefetched.get('images')
		if prefetched_images:
			first_image = prefetched_images[0]
			if first_image and first_image.image:
				return first_image.image.url

		first_image = self.images.order_by('id').first()
		if first_image and first_image.image:
			return first_image.image.url

		if self.asset_image:
			return self.asset_image.url

		return ''

	def get_stock_status(self):
		"""Return stock status: 'instock', 'low stock', or 'out of stock'"""
		total_stock = self.get_total_stock_quantity()
		threshold = self.get_effective_low_stock_threshold()
		if total_stock == 0:
			return 'out of stock'
		elif total_stock <= threshold:
			return 'low stock'
		return 'instock'

	def get_inventory_root(self):
		if self.parent_item_id:
			return self.parent_item
		return self

	def get_inventory_group_queryset(self):
		root = self.get_inventory_root()
		return AssetItem.objects.filter(Q(pk=root.pk) | Q(parent_item_id=root.pk))

	def get_total_stock_quantity(self):
		return self.get_inventory_group_queryset().aggregate(total=Sum('stock_quantity')).get('total') or 0

	def get_effective_low_stock_threshold(self):
		root = self.get_inventory_root()
		return root.low_stock_threshold

	def deduct_stock(self, quantity, accountability_entry=None):
		"""Deduct stock from shared inventory pool (parent + variants)."""
		if quantity < 1:
			raise ValidationError('Quantity must be at least 1.')

		available_total = self.get_total_stock_quantity()
		if quantity > available_total:
			raise ValidationError(f'Insufficient stock. Available: {available_total}, Requested: {quantity}')

		root = self.get_inventory_root()
		items = list(AssetItem.objects.filter(Q(pk=root.pk) | Q(parent_item_id=root.pk)).order_by('id'))
		items_by_id = {item.pk: item for item in items}

		ordered_items = []
		added_ids = set()

		def _push(item_obj):
			if item_obj and item_obj.pk not in added_ids:
				ordered_items.append(item_obj)
				added_ids.add(item_obj.pk)

		_push(items_by_id.get(root.pk))
		_push(items_by_id.get(self.pk))
		for item_obj in items:
			_push(item_obj)

		remaining = quantity
		for item_obj in ordered_items:
			if remaining <= 0:
				break
			if item_obj.stock_quantity <= 0:
				continue
			deduct_amount = min(item_obj.stock_quantity, remaining)
			item_obj.stock_quantity -= deduct_amount
			item_obj.save(update_fields=['stock_quantity', 'updated_at'])
			remaining -= deduct_amount

		if remaining > 0:
			raise ValidationError('Unable to complete stock deduction due to stock synchronization issue.')
		return True

	def restore_stock(self, quantity):
		"""Restore stock back to root inventory pool."""
		if quantity < 1:
			return False
		root = self.get_inventory_root()
		root.stock_quantity += quantity
		root.save(update_fields=['stock_quantity', 'updated_at'])
		return True


class AssetItemImage(models.Model):
	item = models.ForeignKey(AssetItem, on_delete=models.CASCADE, related_name='images')
	image = models.ImageField(upload_to='asset_images/')
	uploaded_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['id']

	def __str__(self):
		return f'AssetItemImage<{self.item_id}:{self.image.name}>'


class AssetTagBatch(models.Model):
	department = models.ForeignKey(AssetDepartment, on_delete=models.SET_NULL, null=True, blank=True, related_name='tag_batches')
	generated_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='asset_tag_batches_generated',
	)
	notes = models.CharField(max_length=255, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		scope = self.department.name if self.department else 'All Departments'
		return f'AssetTagBatch<{scope}:{self.created_at:%Y-%m-%d %H:%M}>'


class AssetTagEntry(models.Model):
	batch = models.ForeignKey(AssetTagBatch, on_delete=models.CASCADE, related_name='entries')
	item = models.ForeignKey(AssetItem, on_delete=models.SET_NULL, null=True, blank=True, related_name='tag_entries')
	tag_code = models.CharField(max_length=30)
	item_code_snapshot = models.CharField(max_length=20)
	item_name_snapshot = models.CharField(max_length=150)
	specification_snapshot = models.CharField(max_length=255, blank=True)
	department_name_snapshot = models.CharField(max_length=100)
	parent_item_code_snapshot = models.CharField(max_length=20, blank=True)
	sequence = models.PositiveIntegerField(default=1)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['item_code_snapshot', 'sequence']
		constraints = [
			models.UniqueConstraint(fields=['batch', 'tag_code'], name='unique_asset_tag_code_per_batch'),
		]

	def __str__(self):
		return self.tag_code


class AssetAccountability(models.Model):
	REQUEST_STATUS_CHOICES = [
		('pending', 'Pending Approval'),
		('approved', 'Approved'),
		('declined', 'Declined'),
	]
	STATUS_CHOICES = [
		('borrowed', 'Borrowed'),
		('returned', 'Returned'),
	]

	item = models.ForeignKey(AssetItem, on_delete=models.PROTECT, related_name='accountabilities')
	borrowed_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='asset_accountabilities'
	)
	quantity_borrowed = models.PositiveIntegerField(default=1)
	date_borrowed = models.DateTimeField(auto_now_add=True)
	date_returned = models.DateTimeField(null=True, blank=True)
	request_status = models.CharField(max_length=20, choices=REQUEST_STATUS_CHOICES, default='approved')
	decision_reason = models.TextField(blank=True)
	processed_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='asset_accountability_processed',
	)
	processed_at = models.DateTimeField(null=True, blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='borrowed')
	notes = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['-date_borrowed']
		permissions = [
			('can_borrow_assets', 'Can borrow assets'),
			('can_manage_accountability', 'Can manage asset accountability'),
		]

	def __str__(self):
		return f'{self.borrowed_by.get_full_name() or self.borrowed_by.username} - {self.item.item_code} ({self.quantity_borrowed}x)'

	def mark_approved(self, processed_by=None, reason=''):
		"""Approve borrow request and deduct stock once."""
		if self.request_status != 'pending':
			return False

		self.item.deduct_stock(self.quantity_borrowed)
		self.request_status = 'approved'
		self.status = 'borrowed'
		self.processed_by = processed_by
		self.processed_at = timezone.now()
		self.decision_reason = reason or ''
		self.save(update_fields=['request_status', 'status', 'processed_by', 'processed_at', 'decision_reason', 'updated_at'])
		return True

	def mark_declined(self, processed_by=None, reason=''):
		"""Decline pending borrow request without changing stock."""
		if self.request_status != 'pending':
			return False

		self.request_status = 'declined'
		self.processed_by = processed_by
		self.processed_at = timezone.now()
		self.decision_reason = reason or ''
		self.save(update_fields=['request_status', 'processed_by', 'processed_at', 'decision_reason', 'updated_at'])
		return True

	def mark_returned(self):
		"""Mark item as returned and restore stock"""
		if self.request_status != 'approved':
			return False
		if self.status != 'returned':
			self.status = 'returned'
			self.date_returned = timezone.now()
			self.item.restore_stock(self.quantity_borrowed)
			self.save(update_fields=['status', 'date_returned', 'updated_at'])
			return True
		return False


class AssetReturnProof(models.Model):
	accountability = models.ForeignKey(AssetAccountability, on_delete=models.CASCADE, related_name='return_proofs')
	image = models.ImageField(upload_to=accountability_return_proof_upload_to)
	uploaded_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='asset_return_proofs_uploaded',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'ReturnProof<{self.accountability_id}:{self.image.name}>'


class CompanyInternetAccount(models.Model):
	AUTH_PROVIDER_CHOICES = [
		('native', 'Native Username/Password'),
		('google', 'Sign in with Google'),
		('facebook', 'Sign in with Facebook'),
		('microsoft', 'Sign in with Microsoft'),
		('apple', 'Sign in with Apple'),
		('other', 'Other SSO/Provider'),
	]

	platform_name = models.CharField(max_length=120)
	website_url = models.URLField(blank=True)
	account_identifier = models.CharField(max_length=190, help_text='Main login identifier (username/email/phone).')
	login_email = models.EmailField(blank=True)
	auth_provider = models.CharField(max_length=24, choices=AUTH_PROVIDER_CHOICES, default='native')
	credential_username = models.CharField(max_length=190, blank=True)
	encrypted_password = models.TextField()
	holder_name_override = models.CharField(max_length=150, blank=True)
	notes = models.TextField(blank=True)
	submitted_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='company_internet_accounts',
	)
	last_unlocked_at = models.DateTimeField(blank=True, null=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ['-created_at']
		permissions = [
			('reveal_companyinternetaccount_password', 'Can reveal company internet account passwords'),
		]

	def __str__(self):
		return f'CompanyInternetAccount<{self.platform_name}:{self.account_identifier}>'

	@property
	def masked_password(self):
		return '************'

	def set_credential_password(self, raw_password):
		password_text = (raw_password or '').strip()
		if not password_text:
			raise ValidationError({'encrypted_password': 'Password is required for this credential record.'})
		self.encrypted_password = _credentials_fernet().encrypt(password_text.encode('utf-8')).decode('utf-8')

	def get_credential_password(self):
		if not self.encrypted_password:
			return ''
		try:
			return _credentials_fernet().decrypt(self.encrypted_password.encode('utf-8')).decode('utf-8')
		except (InvalidToken, ValueError, ValidationError):
			return ''

	def get_holder_display_name(self):
		manual_holder = (self.holder_name_override or '').strip()
		if manual_holder:
			return manual_holder
		if not self.submitted_by:
			return 'Unknown'
		return self.submitted_by.get_full_name() or self.submitted_by.username


database_storage = FileSystemStorage(location=Path(settings.BASE_DIR) / 'database')


def database_file_upload_to(instance, filename):
	original_name = filename or 'database.file'
	extension = Path(original_name).suffix or '.file'
	safe_name = slugify(instance.database_name or 'database') or 'database'
	random_suffix = uuid.uuid4().hex[:8]
	return f'{safe_name}/{safe_name}_{random_suffix}{extension.lower()}'


class DevelopmentFeedback(models.Model):
	CATEGORY_CHOICES = [
		('suggestion', 'Suggestion'),
		('bug_report', 'Bug Report'),
		('comment', 'Comment'),
	]

	STATUS_CHOICES = [
		('new', 'New'),
		('in_review', 'In Review'),
		('resolved', 'Resolved'),
	]

	title = models.CharField(max_length=150)
	category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='suggestion')
	message = models.TextField()
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='development_feedback_submissions',
	)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'DevelopmentFeedback<{self.category}:{self.title}>'


class DevelopmentFeedbackComment(models.Model):
	feedback = models.ForeignKey(DevelopmentFeedback, on_delete=models.CASCADE, related_name='comments')
	comment = models.TextField()
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='development_feedback_comments_created',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['created_at']

	def __str__(self):
		return f'DevelopmentFeedbackComment<{self.feedback_id}:{self.created_by_id}>'


class PatchNote(models.Model):
	version = models.CharField(max_length=30)
	title = models.CharField(max_length=150)
	details = models.TextField()
	is_published = models.BooleanField(default=True)
	published_at = models.DateField(default=timezone.localdate)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='patch_notes_created',
	)

	class Meta:
		ordering = ['-published_at', '-created_at']

	def __str__(self):
		return f'PatchNote<{self.version}:{self.title}>'


class PatchNoteComment(models.Model):
	patch_note = models.ForeignKey(PatchNote, on_delete=models.CASCADE, related_name='comments')
	comment = models.TextField()
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='patch_note_comments_created',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['created_at']

	def __str__(self):
		return f'PatchNoteComment<{self.patch_note_id}:{self.created_by_id}>'


class PatchNoteReaction(models.Model):
	REACTION_CHOICES = [
		('like', 'Like'),
		('love', 'Love'),
		('celebrate', 'Celebrate'),
		('insightful', 'Insightful'),
	]

	patch_note = models.ForeignKey(PatchNote, on_delete=models.CASCADE, related_name='reactions')
	reaction = models.CharField(max_length=20, choices=REACTION_CHOICES, default='like')
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='patch_note_reactions_created',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-created_at']
		constraints = [
			models.UniqueConstraint(
				fields=['patch_note', 'created_by'],
				name='unique_patch_note_reaction_per_user',
			),
		]

	def __str__(self):
		return f'PatchNoteReaction<{self.patch_note_id}:{self.created_by_id}:{self.reaction}>'


def patch_note_attachment_upload_to(instance, filename):
	original_name = filename or 'attachment.file'
	extension = Path(original_name).suffix.lower() or '.file'
	date_prefix = timezone.localtime(timezone.now()).strftime('%Y/%m')
	random_suffix = uuid.uuid4().hex[:10]
	return f'patch_notes/{date_prefix}/attachment_{random_suffix}{extension}'


class PatchNoteAttachment(models.Model):
	patch_note = models.ForeignKey(PatchNote, on_delete=models.CASCADE, related_name='attachments')
	file = models.FileField(upload_to=patch_note_attachment_upload_to)
	uploaded_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='patch_note_attachments_uploaded',
	)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['created_at']

	def __str__(self):
		return f'PatchNoteAttachment<{self.patch_note_id}:{self.file.name}>'


class DatabaseFile(models.Model):
	DATABASE_TYPE_CHOICES = [
		('sqlite', 'SQLite'),
		('mysql', 'MySQL'),
		('mariadb', 'MariaDB'),
		('postgresql', 'PostgreSQL'),
		('oracle', 'Oracle'),
		('sqlserver', 'SQL Server'),
		('other', 'Other'),
	]

	database_type = models.CharField(max_length=20, choices=DATABASE_TYPE_CHOICES, default='sqlite')
	database_name = models.CharField(max_length=120)
	file = models.FileField(upload_to=database_file_upload_to, storage=database_storage)
	notes = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	uploaded_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='database_files_uploaded',
	)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'DatabaseFile<{self.database_type}:{self.database_name}>'


class SystemBackupSchedule(models.Model):
	JOB_TYPE_CHOICES = [
		('backup_only', 'Backup Only'),
		('backup_cleanup', 'Backup + Cleanup'),
		('backup_verify', 'Backup + Verify'),
	]

	name = models.CharField(max_length=100, default='Primary Backup Schedule')
	is_enabled = models.BooleanField(default=True)
	job_type = models.CharField(max_length=20, choices=JOB_TYPE_CHOICES, default='backup_cleanup')
	cron_minute = models.PositiveSmallIntegerField(default=0)
	max_backups = models.PositiveSmallIntegerField(default=10)
	include_logs = models.BooleanField(default=True)
	include_docs = models.BooleanField(default=True)
	include_media = models.BooleanField(default=True)
	include_database = models.BooleanField(default=True)
	include_static = models.BooleanField(default=False)
	include_templates = models.BooleanField(default=False)
	last_run_at = models.DateTimeField(blank=True, null=True)
	updated_at = models.DateTimeField(auto_now=True)
	updated_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='system_backup_schedules_updated',
	)

	class Meta:
		ordering = ['id']

	def __str__(self):
		return f'SystemBackupSchedule<{self.name}>'

	def clean(self):
		if self.cron_minute > 59:
			raise ValidationError({'cron_minute': 'Cron minute must be between 0 and 59.'})
		allowed_job_types = {choice[0] for choice in self.JOB_TYPE_CHOICES}
		if self.job_type not in allowed_job_types:
			raise ValidationError({'job_type': 'Invalid backup job type.'})
		if self.max_backups < 1 or self.max_backups > 10:
			raise ValidationError({'max_backups': 'Max backups must be between 1 and 10.'})


def system_backup_upload_to(instance, filename):
	original_name = filename or 'system-backup.zip'
	date_prefix = timezone.localtime(timezone.now()).strftime('%Y/%m')
	extension = Path(original_name).suffix.lower() or '.zip'
	random_suffix = uuid.uuid4().hex[:10]
	return f'system_backups/{date_prefix}/backup_{random_suffix}{extension}'


class SystemBackup(models.Model):
	TRIGGER_CHOICES = [
		('manual', 'Manual'),
		('scheduled', 'Scheduled'),
	]

	schedule = models.ForeignKey(
		SystemBackupSchedule,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='backups',
	)
	backup_name = models.CharField(max_length=180)
	archive = models.FileField(upload_to=system_backup_upload_to)
	included_scopes = models.CharField(max_length=255)
	trigger = models.CharField(max_length=20, choices=TRIGGER_CHOICES, default='manual')
	notes = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	created_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
		related_name='system_backups_created',
	)
	last_restored_at = models.DateTimeField(blank=True, null=True)
	restore_count = models.PositiveIntegerField(default=0)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		return f'SystemBackup<{self.backup_name}>'

	@property
	def included_scopes_list(self):
		return [item.strip() for item in (self.included_scopes or '').split(',') if item.strip()]

	@property
	def archive_size_bytes(self):
		try:
			return int(self.archive.size or 0)
		except Exception:
			return 0
