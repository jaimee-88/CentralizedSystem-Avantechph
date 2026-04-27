import json
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

from captcha.fields import CaptchaField
from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, UserCreationForm
from django.contrib.auth.models import Group, Permission, User
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.conf import settings
from django.utils.dateparse import parse_date
from PIL import Image

from .auth_utils import get_client_ip
from .permission_catalog import build_permission_groups
from .models import (
    AssetAccountability,
    AssetDepartment,
    AssetItem,
    AssetItemImage,
    AssetItemType,
    Client,
    ClientQuotation,
    CompanyInternetAccount,
    DevelopmentFeedback,
    FundRequest,
    FundRequestAttachment,
    FundRequestLineItem,
    FundRequestTemplate,
    Liquidation,
    LiquidationAttachment,
    LiquidationLineItem,
    LiquidationTemplate,
    SupportTicket,
    SupportTicketMessage,
    PatchNote,
    PatchNoteAttachment,
    PatchNoteComment,
    UserProfile,
)


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('widget', MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            cleaned_files = [single_file_clean(item, initial) for item in data if item]
        elif data:
            cleaned_files = [single_file_clean(data, initial)]
        else:
            cleaned_files = []
        return cleaned_files


class BaseUserFormMixin:
    def _selected_field_values(self, field_name):
        """Return selected values for a multi-select field as strings.

        Django's BoundField.value() can be empty on unbound edit forms depending
        on widget/state. Fall back to initial and instance relations so the UI
        reliably reflects existing assignments.
        """
        raw_values = self[field_name].value()

        if raw_values in (None, ''):
            raw_values = self.initial.get(field_name)

        if raw_values in (None, '') and getattr(self.instance, 'pk', None):
            if field_name == 'user_permissions':
                raw_values = list(self.instance.user_permissions.values_list('pk', flat=True))
            elif field_name == 'groups':
                raw_values = list(self.instance.groups.values_list('pk', flat=True))

        if raw_values is None:
            return set()

        if not isinstance(raw_values, (list, tuple, set)):
            raw_values = [raw_values]

        normalized = set()
        for value in raw_values:
            if hasattr(value, 'pk'):
                normalized.add(str(value.pk))
            else:
                normalized.add(str(value))

        return normalized

    def _style_fields(self):
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxSelectMultiple):
                field.widget.attrs.setdefault('class', 'checkbox-list')
            elif isinstance(field.widget, (forms.SelectMultiple,)):
                field.widget.attrs.setdefault('class', 'form-select')
            elif isinstance(field.widget, (forms.CheckboxInput,)):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')

            if field_name in {'groups', 'user_permissions'}:
                field.widget.attrs.setdefault('data-field-kind', field_name)

    def build_grouped_permissions(self, field_name):
        field = self.fields[field_name]
        selected_values = self._selected_field_values(field_name)
        return build_permission_groups(field.queryset, selected_values=selected_values)


class StaffUserCreationForm(BaseUserFormMixin, UserCreationForm):
    branch = forms.CharField(required=False, max_length=120)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = [
            'username',
            'first_name',
            'last_name',
            'email',
            'branch',
            'is_active',
            'is_staff',
            'groups',
            'user_permissions',
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['groups'].queryset = Group.objects.order_by('name')
        self.fields['groups'].label = 'Roles'
        self.fields['groups'].widget = forms.CheckboxSelectMultiple()
        self.fields['groups'].widget.choices = self.fields['groups'].choices
        self.fields['groups'].help_text = 'Check one or more roles to assign to this user.'
        self.fields['user_permissions'].queryset = Permission.objects.order_by('content_type__app_label', 'codename')
        self.fields['user_permissions'].widget = forms.CheckboxSelectMultiple()
        self.fields['user_permissions'].widget.choices = self.fields['user_permissions'].choices
        self.fields['user_permissions'].label = 'Feature Access Overrides'
        self.fields['user_permissions'].help_text = (
            'Optional. Use this only for special cases when a user needs access different from their assigned roles.'
        )
        self.fields['branch'].label = 'Branch'
        self.fields['branch'].help_text = 'Optional branch assignment (e.g., Main, North, South).'
        self._style_fields()

    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit and user:
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.branch = (self.cleaned_data.get('branch') or '').strip()
            profile.save(update_fields=['branch'])
        return user

    @property
    def grouped_user_permissions(self):
        return self.build_grouped_permissions('user_permissions')


class StaffUserUpdateForm(BaseUserFormMixin, forms.ModelForm):
    branch = forms.CharField(required=False, max_length=120)

    class Meta:
        model = User
        fields = [
            'username',
            'first_name',
            'last_name',
            'email',
            'branch',
            'is_active',
            'is_staff',
            'groups',
            'user_permissions',
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['groups'].queryset = Group.objects.order_by('name')
        self.fields['groups'].label = 'Roles'
        self.fields['groups'].widget = forms.CheckboxSelectMultiple()
        self.fields['groups'].widget.choices = self.fields['groups'].choices
        self.fields['groups'].help_text = 'Check one or more roles to assign to this user.'
        self.fields['user_permissions'].queryset = Permission.objects.order_by('content_type__app_label', 'codename')
        self.fields['user_permissions'].widget = forms.CheckboxSelectMultiple()
        self.fields['user_permissions'].widget.choices = self.fields['user_permissions'].choices
        self.fields['user_permissions'].label = 'Feature Access Overrides'
        self.fields['user_permissions'].help_text = (
            'Optional. Use this only for special cases when a user needs access different from their assigned roles.'
        )
        profile = getattr(self.instance, 'profile', None)
        self.fields['branch'].initial = profile.branch if profile else ''
        self.fields['branch'].label = 'Branch'
        self.fields['branch'].help_text = 'Optional branch assignment (e.g., Main, North, South).'
        self._style_fields()

    def save(self, commit=True):
        user = super().save(commit=commit)
        if commit and user:
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.branch = (self.cleaned_data.get('branch') or '').strip()
            profile.save(update_fields=['branch'])
        return user

    @property
    def grouped_user_permissions(self):
        return self.build_grouped_permissions('user_permissions')


class RoleForm(BaseUserFormMixin, forms.ModelForm):
    class Meta:
        model = Group
        fields = ['name', 'permissions']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['permissions'].queryset = Permission.objects.order_by('content_type__app_label', 'codename')
        self.fields['permissions'].widget = forms.CheckboxSelectMultiple()
        self.fields['permissions'].widget.choices = self.fields['permissions'].choices
        self.fields['permissions'].label = 'Feature Access'
        self.fields['permissions'].help_text = 'Select which system features this role can access.'
        self.fields['name'].widget.attrs.update({'class': 'form-control'})
        self.fields['permissions'].widget.attrs.update({'class': 'checkbox-list', 'data-field-kind': 'permissions'})

    @property
    def grouped_permissions(self):
        return self.build_grouped_permissions('permissions')


class SecureAuthenticationForm(AuthenticationForm):
    captcha = CaptchaField()

    error_messages = {
        'invalid_login': 'Invalid login credentials. Please try again.',
        'inactive': 'Invalid login credentials. Please try again.',
    }

    def __init__(self, request=None, *args, **kwargs):
        super().__init__(request, *args, **kwargs)
        self.fields['username'].widget.attrs.update({'class': 'form-control', 'autocomplete': 'username'})
        self.fields['password'].widget.attrs.update({'class': 'form-control', 'autocomplete': 'current-password'})
        self.fields['captcha'].widget.attrs.update({'class': 'form-control'})

    def clean(self):
        username = self.data.get('username', '').strip().lower()
        ip_address = get_client_ip(self.request) if self.request else 'unknown'
        cache_key = f'login-fail:{ip_address}:{username}'
        attempts = int(cache.get(cache_key, 0))

        if attempts > 0:
            time.sleep(min(attempts * 0.4, 2.0))

        try:
            cleaned_data = super().clean()
        except ValidationError:
            cache.set(cache_key, attempts + 1, timeout=15 * 60)
            raise ValidationError(self.error_messages['invalid_login'])

        cache.delete(cache_key)
        return cleaned_data


class OTPVerificationForm(forms.Form):
    token = forms.CharField(
        label='Authenticator code',
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'one-time-code'}),
    )


class EmailVerificationRequestForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'autocomplete': 'email'}))


class EmailVerificationOTPForm(forms.Form):
    otp = forms.CharField(
        label='Verification code',
        min_length=6,
        max_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'inputmode': 'numeric', 'autocomplete': 'one-time-code'}),
    )

    def clean_otp(self):
        otp = (self.cleaned_data.get('otp') or '').strip()
        if not otp.isdigit():
            raise ValidationError('Enter the 6-digit verification code.')
        return otp


class LockoutResetForm(forms.Form):
    username = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))
    ip_address = forms.GenericIPAddressField(required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        ip_address = cleaned_data.get('ip_address')

        if not username and not ip_address:
            raise ValidationError('Provide at least a username or IP address to unlock.')

        return cleaned_data


class SecurePasswordChangeForm(PasswordChangeForm):
    captcha = CaptchaField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_messages['password_incorrect'] = 'Current password is incorrect. Please enter your current password.'

        self.fields['old_password'].required = True
        self.fields['new_password1'].required = True
        self.fields['new_password2'].required = True
        self.fields['captcha'].required = True

        self.fields['old_password'].error_messages['required'] = 'Current password is required.'
        self.fields['new_password1'].error_messages['required'] = 'New password is required.'
        self.fields['new_password2'].error_messages['required'] = 'Please confirm your new password.'
        self.fields['captcha'].error_messages['required'] = 'Captcha is required.'
        self.fields['captcha'].error_messages['invalid'] = 'Captcha is incorrect. Please try again.'

        self.fields['old_password'].widget.attrs.update({'class': 'form-control', 'autocomplete': 'current-password'})
        self.fields['new_password1'].widget.attrs.update({'class': 'form-control', 'autocomplete': 'new-password'})
        self.fields['new_password2'].widget.attrs.update({'class': 'form-control', 'autocomplete': 'new-password'})
        self.fields['captcha'].widget.attrs.update({'class': 'form-control'})
        self.fields['old_password'].widget.attrs.update({'required': 'required'})
        self.fields['new_password1'].widget.attrs.update({'required': 'required'})
        self.fields['new_password2'].widget.attrs.update({'required': 'required'})
        self.fields['captcha'].widget.attrs.update({'required': 'required'})

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        if not old_password:
            raise ValidationError('Current password is required.')
        if not self.user.check_password(old_password):
            raise ValidationError('Current password is incorrect. Please enter your current password.')
        return old_password


class UserStatusForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['status']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['status'].choices = [
            ('active', 'Active'),
            ('idle', 'Idle'),
            ('offline', 'Offline'),
        ]
        self.fields['status'].widget.attrs.update({'class': 'form-select'})
        self.fields['status'].label = 'Set your status'


class ClientForm(forms.ModelForm):
    class Meta:
        model = Client
        fields = [
            'full_name',
            'exact_address',
            'active_phone_number',
            'email',
            'average_monthly_electricity_bill',
            'usage_of_electricity',
            'appliances_and_electric_things',
            'property_status',
            'client_type',
            'status',
            'lead_status',
            'lead_disposition_reason',
            'lead_proof_image',
            'handled_by',
            'handled_date',
        ]
        widgets = {
            'exact_address': forms.Textarea(attrs={'rows': 3}),
            'appliances_and_electric_things': forms.Textarea(attrs={'rows': 4}),
            'lead_disposition_reason': forms.Textarea(attrs={'rows': 3}),
            'handled_date': forms.DateInput(attrs={'type': 'date'}),
            'lead_proof_image': forms.ClearableFileInput(attrs={'accept': '.png,.jpg,.jpeg,.webp'}),
        }

    def __init__(self, *args, **kwargs):
        self.current_user = kwargs.pop('current_user', None)
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.Select):
                field.widget.attrs.setdefault('class', 'form-select')
            else:
                field.widget.attrs.setdefault('class', 'form-control')

        self.fields['handled_by'].required = False
        self.fields['lead_disposition_reason'].required = False
        self.fields['lead_proof_image'].required = False

        # Status and lead lifecycle are managed through quotation records.
        self.fields['status'].disabled = True
        self.fields['lead_status'].disabled = True
        if self.instance and self.instance.pk:
            self.fields['status'].initial = self.instance.status
            self.fields['lead_status'].initial = self.instance.lead_status
        else:
            self.fields['status'].initial = 'inquiry'
            self.fields['lead_status'].initial = 'intake'

        self.fields['status'].help_text = 'Read-only. Updated via quotation records only.'
        self.fields['lead_status'].help_text = 'Read-only. Updated via quotation records only.'

        if self.current_user and not self.current_user.is_superuser:
            self.fields['handled_by'].queryset = User.objects.filter(pk=self.current_user.pk)
            self.fields['handled_by'].initial = self.current_user
            self.fields['handled_by'].widget = forms.HiddenInput()

        # On Add Client, hide lead outcome fields. These are managed by quotation workflow.
        if not (self.instance and self.instance.pk):
            self.fields.pop('lead_disposition_reason', None)
            self.fields.pop('lead_proof_image', None)

    def clean_handled_by(self):
        if self.current_user and not self.current_user.is_superuser:
            return self.current_user
        return self.cleaned_data.get('handled_by')

    def clean_lead_proof_image(self):
        file = self.cleaned_data.get('lead_proof_image')
        if not file:
            return file

        allowed_extensions = {'.png', '.jpg', '.jpeg', '.webp'}
        name = (file.name or '').lower()
        if '.' not in name or not any(name.endswith(ext) for ext in allowed_extensions):
            raise ValidationError('Upload a valid proof image file (PNG, JPG, JPEG, WEBP).')

        max_size_bytes = 10 * 1024 * 1024
        if getattr(file, 'size', 0) > max_size_bytes:
            raise ValidationError('Proof image size must be 10MB or less.')

        return file

    def clean(self):
        cleaned_data = super().clean()

        if self.instance and self.instance.pk:
            cleaned_data['status'] = self.instance.status
            cleaned_data['lead_status'] = self.instance.lead_status
        else:
            cleaned_data['status'] = 'inquiry'
            cleaned_data['lead_status'] = 'intake'

        return cleaned_data


class ClientQuotationForm(forms.ModelForm):
    REASON_REQUIRED_LEAD_STATUSES = {'lost', 'not_qualified'}
    MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
    LEAD_STATUS_OPTIONS = [
        ('', 'Select lead status'),
        ('intake', 'Intake'),
        ('qualified', 'Qualified'),
        ('lost', 'Lost'),
        ('not_qualified', 'Not Qualified'),
        ('converted', 'Converted'),
    ]
    lead_status = forms.ChoiceField(choices=LEAD_STATUS_OPTIONS, required=True)
    lead_disposition_reason = forms.CharField(
        required=False,
        label='Reason (for Lost / Not Qualified)',
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Enter reason when lead status is Lost or Not Qualified.'}),
    )

    class Meta:
        model = ClientQuotation
        fields = ['product_package', 'quoted_amount', 'negotiation_status', 'quotation_notes', 'scanned_document']
        widgets = {
            'quotation_notes': forms.Textarea(attrs={'rows': 4}),
            'scanned_document': forms.ClearableFileInput(attrs={'accept': '*/*'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['lead_status'].choices = self.LEAD_STATUS_OPTIONS
        self.fields['documents'] = MultipleFileField(
            required=False,
            widget=MultipleFileInput(attrs={'accept': '*/*', 'multiple': True, 'class': 'd-none'}),
            label='Any Documentation',
            help_text='Recommended: upload any supporting documentation (images, PDFs, office files, videos, and more).',
        )
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.Select):
                field.widget.attrs.setdefault('class', 'form-select')
            else:
                field.widget.attrs.setdefault('class', 'form-control')

    def clean_scanned_document(self):
        file = self.cleaned_data.get('scanned_document')
        if not file:
            return file

        if getattr(file, 'size', 0) > self.MAX_FILE_SIZE_BYTES:
            raise ValidationError('File size must be 100MB or less.')

        return file

    def clean_documents(self):
        files = self.cleaned_data.get('documents') or []
        for file in files:
            if getattr(file, 'size', 0) > self.MAX_FILE_SIZE_BYTES:
                raise ValidationError('Each uploaded file must be 100MB or less.')
        return files

    def clean(self):
        cleaned_data = super().clean()
        lead_status = (cleaned_data.get('lead_status') or '').strip()
        reason = (cleaned_data.get('lead_disposition_reason') or '').strip()

        if lead_status in self.REASON_REQUIRED_LEAD_STATUSES and not reason:
            self.add_error('lead_disposition_reason', 'Reason is required when lead status is Lost or Not Qualified.')

        cleaned_data['lead_disposition_reason'] = reason

        return cleaned_data


class FundRequestTemplateForm(forms.ModelForm):
    MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx'}

    class Meta:
        model = FundRequestTemplate
        fields = ['name', 'file', 'notes', 'is_active']
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 3}),
            'file': forms.ClearableFileInput(attrs={'accept': '.pdf,.doc,.docx,.xls,.xlsx'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')
        self.fields['is_active'].help_text = 'When enabled, new fund requests will use this as the preferred template.'

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if not file:
            return file

        extension = Path(file.name or '').suffix.lower()
        if extension not in self.ALLOWED_EXTENSIONS:
            raise ValidationError('Upload a PDF, DOC, DOCX, XLS, or XLSX template file.')
        if getattr(file, 'size', 0) > self.MAX_FILE_SIZE_BYTES:
            raise ValidationError('Template file size must be 25MB or less.')
        return file


class FundRequestForm(forms.ModelForm):
    line_items_payload = forms.CharField(widget=forms.HiddenInput())
    request_images = MultipleFileField(
        required=True,
        widget=MultipleFileInput(attrs={'class': 'form-control', 'accept': '.png,.jpg,.jpeg,.webp', 'multiple': True}),
        label='Supporting Images',
        help_text='Upload one or more supporting images. These will be appended as extra pages after the generated template PDF.',
    )
    MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024
    ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp'}

    class Meta:
        model = FundRequest
        fields = ['requester_name', 'request_date', 'department', 'branch']
        widgets = {
            'request_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        self._request_user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            field.widget.attrs.setdefault('class', 'form-control')
        self.fields['requester_name'].required = False
        if not self.initial.get('requester_name'):
            default_name = self._default_requester_name()
            if default_name:
                self.fields['requester_name'].initial = default_name
                self.initial['requester_name'] = default_name
        self._parsed_line_items = []

    def _default_requester_name(self):
        if not self._request_user:
            return ''
        full_name = (self._request_user.get_full_name() or '').strip()
        if full_name:
            return full_name
        return (self._request_user.username or '').strip()

    def clean_requester_name(self):
        requester_name = (self.cleaned_data.get('requester_name') or '').strip()
        if requester_name:
            return requester_name

        default_name = self._default_requester_name()
        if default_name:
            return default_name

        raise ValidationError('Name is required.')

    def clean_request_images(self):
        files = self.cleaned_data.get('request_images') or []
        if not files:
            raise ValidationError('Upload at least one supporting image.')

        for upload in files:
            extension = Path(getattr(upload, 'name', '')).suffix.lower()
            if extension not in self.ALLOWED_IMAGE_EXTENSIONS:
                raise ValidationError('Upload valid image files only: PNG, JPG, JPEG, or WEBP.')
            if getattr(upload, 'size', 0) > self.MAX_IMAGE_SIZE_BYTES:
                raise ValidationError('Each image must be 10MB or less.')
            try:
                upload.seek(0)
                image = Image.open(upload)
                image.verify()
            except Exception as exc:
                raise ValidationError('One of the uploaded files is not a valid image.') from exc
            finally:
                try:
                    upload.seek(0)
                except Exception:
                    pass
        return files

    def clean_line_items_payload(self):
        raw_payload = (self.cleaned_data.get('line_items_payload') or '').strip()
        if not raw_payload:
            raise ValidationError('Add at least one fund request line item.')

        try:
            parsed = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ValidationError('Line items could not be parsed. Please review the table rows.') from exc

        if not isinstance(parsed, list) or not parsed:
            raise ValidationError('Add at least one fund request line item.')

        cleaned_items = []
        for index, item in enumerate(parsed, start=1):
            if not isinstance(item, dict):
                raise ValidationError(f'Line item #{index} is invalid.')

            entry_date = (item.get('date') or '').strip()
            particulars = (item.get('particulars') or '').strip()
            amount_raw = str(item.get('amount') or '').strip().replace(',', '')

            if not entry_date:
                raise ValidationError(f'Line item #{index} is missing a date.')
            if not particulars:
                raise ValidationError(f'Line item #{index} is missing particulars.')

            try:
                amount = Decimal(amount_raw)
            except (InvalidOperation, TypeError, ValueError) as exc:
                raise ValidationError(f'Line item #{index} has an invalid amount.') from exc

            if amount <= 0:
                raise ValidationError(f'Line item #{index} amount must be greater than zero.')

            cleaned_items.append(
                {
                    'entry_date': entry_date,
                    'particulars': particulars,
                    'amount': amount.quantize(Decimal('0.01')),
                }
            )

        self._parsed_line_items = cleaned_items
        return raw_payload

    def get_line_items(self):
        return list(self._parsed_line_items)

    def save_line_items(self, fund_request):
        if not fund_request or not fund_request.pk:
            return

        FundRequestLineItem.objects.filter(fund_request=fund_request).delete()
        for item in self.get_line_items():
            FundRequestLineItem.objects.create(
                fund_request=fund_request,
                entry_date=item['entry_date'],
                particulars=item['particulars'],
                amount=item['amount'],
            )
        fund_request.refresh_total_amount(save=True)

    def save_attachments(self, fund_request, uploaded_by=None):
        if not fund_request or not fund_request.pk:
            return

        for upload in self.cleaned_data.get('request_images', []):
            FundRequestAttachment.objects.create(
                fund_request=fund_request,
                image=upload,
                uploaded_by=uploaded_by,
            )


class LiquidationTemplateForm(forms.ModelForm):
    MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx'}

    class Meta:
        model = LiquidationTemplate
        fields = ['name', 'file', 'notes', 'is_active']
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 3}),
            'file': forms.ClearableFileInput(attrs={'accept': '.pdf,.doc,.docx,.xls,.xlsx'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')
        self.fields['is_active'].help_text = 'When enabled, new liquidation forms will use this as the preferred template.'

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if not file:
            return file
        extension = Path(file.name or '').suffix.lower()
        if extension not in self.ALLOWED_EXTENSIONS:
            raise ValidationError('Upload a PDF, DOC, DOCX, XLS, or XLSX template file.')
        if getattr(file, 'size', 0) > self.MAX_FILE_SIZE_BYTES:
            raise ValidationError('Template file size must be 25MB or less.')
        return file


class LiquidationForm(forms.ModelForm):
    line_items_payload = forms.CharField(widget=forms.HiddenInput())
    liquidation_images = MultipleFileField(
        required=False,
        widget=MultipleFileInput(attrs={'class': 'form-control', 'accept': '.png,.jpg,.jpeg,.webp', 'multiple': True}),
        label='Supporting Images',
        help_text='Optional. Upload one or more supporting images. These will be appended as extra pages after the generated liquidation PDF.',
    )
    MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024
    ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.webp'}

    class Meta:
        model = Liquidation
        fields = [
            'name',
            'liquidation_date',
            'branch',
            'position',
            'requested_by_name',
            'amount_requested',
            'returned_or_over_type',
            'amount_returned_or_over',
        ]
        widgets = {
            'liquidation_date': forms.DateInput(attrs={'type': 'date'}),
            'returned_or_over_type': forms.RadioSelect(),
        }

    def __init__(self, *args, **kwargs):
        self._request_user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            if isinstance(field.widget, forms.RadioSelect):
                field.widget.attrs.setdefault('class', 'd-flex gap-3 align-items-center')
            elif isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')

        profile = getattr(self._request_user, 'profile', None) if self._request_user else None
        role_names = list(self._request_user.groups.values_list('name', flat=True)) if self._request_user else []
        default_name = ((self._request_user.get_full_name() or '').strip() if self._request_user else '') or ((self._request_user.username or '').strip() if self._request_user else '')
        if default_name and not self.initial.get('name'):
            self.fields['name'].initial = default_name
        if default_name and not self.initial.get('requested_by_name'):
            self.fields['requested_by_name'].initial = default_name
        if profile and profile.branch and not self.initial.get('branch'):
            self.fields['branch'].initial = profile.branch
        if role_names and not self.initial.get('position'):
            self.fields['position'].initial = role_names[0]
        self._parsed_line_items = []

    def clean_name(self):
        value = (self.cleaned_data.get('name') or '').strip()
        if value:
            return value
        raise ValidationError('Name is required.')

    def clean_requested_by_name(self):
        value = (self.cleaned_data.get('requested_by_name') or '').strip()
        if value:
            return value
        raise ValidationError('Requested by is required.')

    def clean_liquidation_images(self):
        files = self.cleaned_data.get('liquidation_images') or []
        if not files:
            return []

        for upload in files:
            extension = Path(getattr(upload, 'name', '')).suffix.lower()
            if extension not in self.ALLOWED_IMAGE_EXTENSIONS:
                raise ValidationError('Upload valid image files only: PNG, JPG, JPEG, or WEBP.')
            if getattr(upload, 'size', 0) > self.MAX_IMAGE_SIZE_BYTES:
                raise ValidationError('Each image must be 10MB or less.')
            try:
                upload.seek(0)
                image = Image.open(upload)
                image.verify()
            except Exception as exc:
                raise ValidationError('One of the uploaded files is not a valid image.') from exc
            finally:
                try:
                    upload.seek(0)
                except Exception:
                    pass
        return files

    def clean_line_items_payload(self):
        raw_payload = (self.cleaned_data.get('line_items_payload') or '').strip()
        if not raw_payload:
            raise ValidationError('Select at least one approved line item.')
        try:
            parsed = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ValidationError('Liquidation line items could not be parsed.') from exc

        if not isinstance(parsed, list) or not parsed:
            raise ValidationError('Select at least one approved line item.')

        cleaned_items = []
        for index, item in enumerate(parsed, start=1):
            if not isinstance(item, dict):
                raise ValidationError(f'Liquidation line item #{index} is invalid.')
            entry_date = (item.get('date') or '').strip()
            fund_form_no = (item.get('fund_form_no') or '').strip()
            description = (item.get('description') or '').strip()
            amount_raw = str(item.get('amount') or '').strip().replace(',', '')
            source_line_item_id = str(item.get('source_line_item_id') or '').strip()

            if not entry_date:
                raise ValidationError(f'Liquidation line item #{index} is missing a date.')
            if not parse_date(entry_date):
                raise ValidationError(f'Liquidation line item #{index} has an invalid date.')
            if not description:
                raise ValidationError(f'Liquidation line item #{index} is missing a description.')

            try:
                amount = Decimal(amount_raw)
            except (InvalidOperation, TypeError, ValueError) as exc:
                raise ValidationError(f'Liquidation line item #{index} has an invalid amount.') from exc
            if amount <= 0:
                raise ValidationError(f'Liquidation line item #{index} amount must be greater than zero.')

            cleaned_items.append(
                {
                    'entry_date': entry_date,
                    'fund_form_no': fund_form_no,
                    'description': description,
                    'amount': amount.quantize(Decimal('0.01')),
                    'source_line_item_id': int(source_line_item_id) if source_line_item_id.isdigit() else None,
                }
            )

        self._parsed_line_items = cleaned_items
        return raw_payload

    def get_line_items(self):
        return list(self._parsed_line_items)

    def save_line_items(self, liquidation):
        if not liquidation or not liquidation.pk:
            return

        LiquidationLineItem.objects.filter(liquidation=liquidation).delete()
        source_ids = [item['source_line_item_id'] for item in self.get_line_items() if item.get('source_line_item_id')]
        source_map = {
            source_item.id: source_item
            for source_item in FundRequestLineItem.objects.select_related('fund_request').filter(id__in=source_ids)
        }
        for item in self.get_line_items():
            source_line_item = source_map.get(item.get('source_line_item_id'))
            LiquidationLineItem.objects.create(
                liquidation=liquidation,
                source_fund_request=getattr(source_line_item, 'fund_request', None),
                source_line_item=source_line_item,
                entry_date=item['entry_date'],
                fund_form_no=item['fund_form_no'],
                description=item['description'],
                amount=item['amount'],
            )
        liquidation.refresh_total_amount(save=True)

    def save_attachments(self, liquidation, uploaded_by=None):
        if not liquidation or not liquidation.pk:
            return

        for upload in self.cleaned_data.get('liquidation_images', []):
            LiquidationAttachment.objects.create(
                liquidation=liquidation,
                image=upload,
                uploaded_by=uploaded_by,
            )


class AssetDepartmentForm(forms.ModelForm):
    class Meta:
        model = AssetDepartment
        fields = ['name']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['name'].widget.attrs.setdefault('class', 'form-control')


class AssetItemTypeForm(forms.ModelForm):
    class Meta:
        model = AssetItemType
        fields = ['name', 'code', 'prefix', 'is_active']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for _, field in self.fields.items():
            if isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')
        self.fields['code'].help_text = 'Unique key used in items (example: cable, laptop, monitor).'
        self.fields['prefix'].help_text = '2-5 alphanumeric prefix for generated item IDs.'

    def clean_code(self):
        return (self.cleaned_data.get('code') or '').strip().lower()

    def clean_prefix(self):
        prefix = (self.cleaned_data.get('prefix') or '').strip().upper()
        if len(prefix) < 2 or len(prefix) > 5 or not prefix.isalnum():
            raise ValidationError('Prefix must be 2-5 alphanumeric characters.')
        return prefix


class AssetItemForm(forms.ModelForm):
    item_type = forms.ChoiceField(widget=forms.Select())
    asset_images = MultipleFileField(required=False)
    remove_image_ids = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = AssetItem
        fields = [
            'department',
            'parent_item',
            'item_name',
            'item_type',
            'code_prefix',
            'specification',
            'note',
            'stock_quantity',
            'low_stock_threshold',
            'is_active',
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, field in self.fields.items():
            if isinstance(field.widget, forms.Select):
                field.widget.attrs.setdefault('class', 'form-select')
            elif isinstance(field.widget, forms.CheckboxInput):
                field.widget.attrs.setdefault('class', 'form-check-input')
            else:
                field.widget.attrs.setdefault('class', 'form-control')

        self.fields['code_prefix'].required = False
        self.fields['code_prefix'].help_text = 'Optional override (e.g. CBL, LP). Leave blank for automatic prefix.'
        self.fields['parent_item'].required = False
        self.fields['asset_images'].required = False
        self.fields['asset_images'].widget.attrs.update({'accept': '.png,.jpg,.jpeg,.webp', 'multiple': True})
        self.fields['asset_images'].help_text = 'Optional. Supports multiple image uploads for both parent and variant items.'
        self.fields['note'].required = False
        self.fields['note'].widget = forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Optional additional note'})

        active_types = list(AssetItemType.objects.filter(is_active=True).order_by('name').values_list('code', 'name'))
        current_type = (getattr(self.instance, 'item_type', '') or '').strip().lower()
        if current_type and current_type not in {code for code, _ in active_types}:
            existing_name = AssetItemType.objects.filter(code=current_type).values_list('name', flat=True).first()
            active_types.append((current_type, existing_name or current_type.replace('-', ' ').title()))
        if not active_types:
            active_types = [('other', 'Other')]
        self.fields['item_type'].choices = active_types
        if current_type:
            self.initial['item_type'] = current_type

        self.fields['parent_item'].queryset = AssetItem.objects.filter(parent_item__isnull=True, is_active=True).order_by('item_code')

        selected_department = self.data.get('department') if self.is_bound else getattr(self.instance, 'department_id', None)
        if selected_department:
            self.fields['parent_item'].queryset = self.fields['parent_item'].queryset.filter(department_id=selected_department)

        if self.instance and self.instance.pk:
            self.fields['parent_item'].queryset = self.fields['parent_item'].queryset.exclude(pk=self.instance.pk)

    def clean_code_prefix(self):
        value = (self.cleaned_data.get('code_prefix') or '').strip().upper()
        if value and (len(value) < 2 or len(value) > 5 or not value.isalnum()):
            raise ValidationError('Code prefix must be 2-5 alphanumeric characters.')
        return value

    def clean(self):
        cleaned_data = super().clean()
        parent_item = cleaned_data.get('parent_item')
        department = cleaned_data.get('department')
        if parent_item and department and parent_item.department_id != department.id:
            self.add_error('parent_item', 'Variant parent must belong to the selected department.')

        return cleaned_data

    def clean_asset_images(self):
        images = self.cleaned_data.get('asset_images') or []
        if not images:
            return []

        allowed_extensions = {'.png', '.jpg', '.jpeg', '.webp'}
        max_size_bytes = 8 * 1024 * 1024
        for image in images:
            name = (image.name or '').lower()
            if '.' not in name or not any(name.endswith(ext) for ext in allowed_extensions):
                raise ValidationError('Upload only valid image files (PNG, JPG, JPEG, WEBP).')
            if getattr(image, 'size', 0) > max_size_bytes:
                raise ValidationError('Each image size must be 8MB or less.')

        return images

    def get_remove_image_ids(self):
        raw = (self.cleaned_data.get('remove_image_ids') or '').strip()
        if not raw:
            return []

        ids = []
        for part in raw.split(','):
            value = part.strip()
            if not value:
                continue
            if not value.isdigit():
                continue
            ids.append(int(value))
        return ids

    def save_images(self, asset_item):
        if not asset_item or not asset_item.pk:
            return

        remove_ids = self.get_remove_image_ids()
        if remove_ids:
            AssetItemImage.objects.filter(item=asset_item, id__in=remove_ids).delete()

        new_images = self.cleaned_data.get('asset_images') or []
        for image in new_images:
            AssetItemImage.objects.create(item=asset_item, image=image)

        first_uploaded = asset_item.images.order_by('id').first()
        asset_item.asset_image = first_uploaded.image if first_uploaded else None
        asset_item.save(update_fields=['asset_image', 'updated_at'])

        return


class AssetAccountabilityForm(forms.ModelForm):
    item = forms.ModelChoiceField(
        queryset=AssetItem.objects.filter(is_active=True),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-select',
            'id': 'accountability_item',
            'data-auto-fill': 'true',
        })
    )
    items = forms.ModelMultipleChoiceField(
        queryset=AssetItem.objects.none(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-select d-none',
            'id': 'accountability_items',
        })
    )
    item_quantities = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = AssetAccountability
        fields = ['item', 'quantity_borrowed', 'notes']
        widgets = {
            'quantity_borrowed': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '1',
                'step': '1',
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Optional notes about the borrowed item',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['quantity_borrowed'].label = 'Quantity'
        self.fields['quantity_borrowed'].required = False
        self.fields['quantity_borrowed'].initial = 1
        self.fields['notes'].required = False

        borrowable_item_ids = []
        for item in AssetItem.objects.filter(is_active=True).select_related('parent_item'):
            total_available = int(item.get_total_stock_quantity() or 0)
            own_stock = int(item.stock_quantity or 0)
            if item.get_stock_status() == 'out of stock':
                continue
            if total_available < 1:
                continue
            if own_stock < 1:
                continue
            borrowable_item_ids.append(item.pk)

        borrowable_queryset = AssetItem.objects.filter(pk__in=borrowable_item_ids).order_by('item_code', 'item_name')
        self.fields['item'].queryset = borrowable_queryset
        self.fields['items'].queryset = borrowable_queryset
        self.fields['item'].label = 'Item'
        self.fields['items'].label = 'Items'
        self.fields['item'].help_text = 'Only items with available stock are shown.'
        self.fields['items'].help_text = 'Select one or more items to borrow.'

        item_label = lambda obj: f"{obj.item_code} - {obj.item_name} - [{(obj.specification or '-').strip() or '-'}]"
        self.fields['item'].label_from_instance = item_label
        self.fields['items'].label_from_instance = item_label

    def clean_quantity_borrowed(self):
        quantity = self.cleaned_data.get('quantity_borrowed')
        if quantity is None:
            return quantity
        if quantity < 1:
            raise ValidationError('Quantity must be at least 1.')
        return quantity

    def clean_item(self):
        item = self.cleaned_data.get('item')
        if not item:
            return item

        if item.get_stock_status() == 'out of stock':
            raise ValidationError('This item is out of stock and cannot be borrowed.')
        if int(item.stock_quantity or 0) < 1:
            raise ValidationError('This item has zero stock and cannot be borrowed.')

        return item

    def clean(self):
        cleaned_data = super().clean()
        selected_items = list(cleaned_data.get('items') or [])
        item = cleaned_data.get('item')
        default_quantity = cleaned_data.get('quantity_borrowed')
        raw_item_quantities = (cleaned_data.get('item_quantities') or '').strip()
        parsed_item_quantities = {}

        if not selected_items and item:
            selected_items = [item]

        if not selected_items:
            self.add_error('items', 'Select at least one item to borrow.')
            return cleaned_data

        cleaned_data['items'] = selected_items

        if raw_item_quantities:
            try:
                decoded = json.loads(raw_item_quantities)
                if isinstance(decoded, dict):
                    parsed_item_quantities = decoded
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed_item_quantities = {}

        item_quantities_map = {}
        unavailable = []
        limited = []

        for selected_item in selected_items:
            item_id_key = str(selected_item.pk)
            selected_quantity = parsed_item_quantities.get(item_id_key, default_quantity)
            try:
                selected_quantity = int(selected_quantity)
            except (TypeError, ValueError):
                self.add_error('items', f'Invalid quantity value for item {selected_item.item_code}.')
                continue

            if selected_quantity < 1:
                self.add_error('items', f'Quantity for item {selected_item.item_code} must be at least 1.')
                continue

            available_total = selected_item.get_total_stock_quantity()
            if available_total < 1:
                unavailable.append(selected_item.item_code)
                continue
            if selected_quantity > available_total:
                limited.append(f'{selected_item.item_code} (available: {available_total})')
                continue

            item_quantities_map[selected_item.pk] = selected_quantity

        if unavailable:
            self.add_error('items', f'Out of stock item(s): {", ".join(unavailable)}')
        if limited:
            self.add_error('items', f'Quantity exceeds availability for: {", ".join(limited)}')

        cleaned_data['item_quantities_map'] = item_quantities_map

        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.request_status = 'pending'
        instance.status = 'borrowed'
        instance.date_returned = None
        
        if commit:
            instance.save()

        return instance


class CompanyInternetAccountForm(forms.ModelForm):
    credential_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'autocomplete': 'new-password'}),
        help_text='Password is encrypted at rest and masked by default in the table.',
    )

    class Meta:
        model = CompanyInternetAccount
        fields = [
            'platform_name',
            'website_url',
            'account_identifier',
            'login_email',
            'auth_provider',
            'credential_username',
            'holder_name_override',
            'notes',
        ]
        widgets = {
            'platform_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Example: Facebook Page, Company Gmail, WordPress'}),
            'website_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://example.com/login'}),
            'account_identifier': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username, email, or account ID'}),
            'login_email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Optional linked email'}),
            'auth_provider': forms.Select(attrs={'class': 'form-select'}),
            'credential_username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional credential username'}),
            'holder_name_override': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Optional holder name override'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Optional notes (scope, recovery details, etc.)'}),
        }

    def clean_credential_password(self):
        password_value = (self.cleaned_data.get('credential_password') or '').strip()
        if not password_value:
            raise ValidationError('Password is required.')
        return password_value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.set_credential_password(self.cleaned_data['credential_password'])
        if commit:
            instance.save()
        return instance


class CompanyInternetAccountUnlockForm(forms.Form):
    current_account_password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'autocomplete': 'current-password'}),
        label='Verify your current account password',
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean_current_account_password(self):
        provided_password = self.cleaned_data.get('current_account_password') or ''
        if not self.user or not isinstance(self.user, User):
            raise ValidationError('Unable to verify password for this session.')
        if not self.user.check_password(provided_password):
            raise ValidationError('Current account password is incorrect.')
        return provided_password


class SupportTicketCreateForm(forms.ModelForm):
    class Meta:
        model = SupportTicket
        fields = ['title', 'category', 'description', 'requested_priority']
        widgets = {
            'title': forms.TextInput(
                attrs={
                    'class': 'form-control',
                    'placeholder': 'Short issue summary',
                }
            ),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 5,
                    'placeholder': 'Describe the issue, steps to reproduce, and affected system.',
                }
            ),
            'requested_priority': forms.Select(attrs={'class': 'form-select'}),
        }

    def clean_title(self):
        title = (self.cleaned_data.get('title') or '').strip()
        if not title:
            raise ValidationError('Ticket title is required.')
        return title

    def clean_description(self):
        description = (self.cleaned_data.get('description') or '').strip()
        if not description:
            raise ValidationError('Ticket description is required.')
        return description


class SupportTicketMessageForm(forms.ModelForm):
    class Meta:
        model = SupportTicketMessage
        fields = ['message']
        widgets = {
            'message': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 3,
                    'placeholder': 'Write your reply...',
                }
            ),
        }

    def clean_message(self):
        message = (self.cleaned_data.get('message') or '').strip()
        if not message:
            raise ValidationError('Message cannot be empty.')
        return message


class SupportTicketRequesterPriorityForm(forms.ModelForm):
    class Meta:
        model = SupportTicket
        fields = ['requested_priority']
        widgets = {
            'requested_priority': forms.Select(attrs={'class': 'form-select form-select-sm'}),
        }


class SupportTicketSupportUpdateForm(forms.ModelForm):
    class Meta:
        model = SupportTicket
        fields = ['status', 'support_priority']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select form-select-sm'}),
            'support_priority': forms.Select(attrs={'class': 'form-select form-select-sm'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['support_priority'].required = False
        self.fields['support_priority'].choices = [('', 'Use End User Priority')] + list(SupportTicket.PRIORITY_CHOICES)


class DeveloperFeedbackForm(forms.ModelForm):
    class Meta:
        model = DevelopmentFeedback
        fields = ['category', 'title', 'message']
        widgets = {
            'category': forms.Select(attrs={'class': 'form-select'}),
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Short summary'}),
            'message': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 5,
                    'placeholder': 'Share your suggestion, bug report details, or general comment.',
                }
            ),
        }


class PatchNoteForm(forms.ModelForm):
    MAX_ATTACHMENTS_PER_NOTE = getattr(settings, 'PATCH_NOTE_MAX_ATTACHMENTS_PER_NOTE', 12)
    MAX_ATTACHMENT_SIZE_BYTES = getattr(settings, 'PATCH_NOTE_MAX_ATTACHMENT_SIZE_BYTES', 150 * 1024 * 1024)
    MAX_TOTAL_UPLOAD_BYTES = getattr(settings, 'PATCH_NOTE_MAX_TOTAL_UPLOAD_BYTES', 500 * 1024 * 1024)
    BLOCKED_ATTACHMENT_EXTENSIONS = {
        '.ade',
        '.adp',
        '.apk',
        '.appx',
        '.bat',
        '.cmd',
        '.com',
        '.cpl',
        '.exe',
        '.hta',
        '.inf',
        '.ins',
        '.isp',
        '.js',
        '.jse',
        '.lnk',
        '.mde',
        '.msc',
        '.msi',
        '.msp',
        '.mst',
        '.pif',
        '.ps1',
        '.reg',
        '.scr',
        '.sct',
        '.sh',
        '.sys',
        '.vb',
        '.vbe',
        '.vbs',
        '.ws',
        '.wsc',
        '.wsf',
        '.wsh',
    }

    attachment_files = MultipleFileField(
        required=False,
        widget=MultipleFileInput(attrs={'class': 'form-control', 'multiple': True}),
        label='Attachments',
        help_text='Upload images, videos, or files. Executable/script files are blocked for safety.',
    )

    class Meta:
        model = PatchNote
        fields = ['version', 'title', 'details', 'published_at', 'is_published']
        widgets = {
            'version': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 1.2.0'}),
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Short update title'}),
            'details': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 4,
                    'placeholder': 'What changed in this release?',
                }
            ),
            'published_at': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'is_published': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def clean_attachment_files(self):
        files = self.cleaned_data.get('attachment_files') or []
        existing_count = self.instance.attachments.count() if getattr(self.instance, 'pk', None) else 0
        if existing_count + len(files) > self.MAX_ATTACHMENTS_PER_NOTE:
            raise ValidationError(
                f'Each patch note supports up to {self.MAX_ATTACHMENTS_PER_NOTE} attachments. '
                f'Current: {existing_count}, new: {len(files)}.'
            )

        total_new_bytes = 0
        for upload in files:
            file_size = getattr(upload, 'size', 0)
            total_new_bytes += file_size

            extension = Path(getattr(upload, 'name', '')).suffix.lower()
            if extension in self.BLOCKED_ATTACHMENT_EXTENSIONS:
                raise ValidationError(f'Blocked file type: {extension or "unknown"}. Please upload a safe file format.')

            if file_size > self.MAX_ATTACHMENT_SIZE_BYTES:
                max_size_mb = self.MAX_ATTACHMENT_SIZE_BYTES // (1024 * 1024)
                raise ValidationError(f'Each attachment must be {max_size_mb}MB or less.')

        if total_new_bytes > self.MAX_TOTAL_UPLOAD_BYTES:
            max_total_mb = self.MAX_TOTAL_UPLOAD_BYTES // (1024 * 1024)
            raise ValidationError(f'Total upload size per request must be {max_total_mb}MB or less.')

        return files

    def scan_attachment(self, upload):
        """Hook for AV integration.

        Replace this method with actual malware scanning logic (e.g. ClamAV or an API service).
        Return (True, '') when safe, otherwise (False, 'reason').
        """
        return True, ''

    def save_attachments(self, patch_note, uploaded_by=None):
        if not patch_note or not patch_note.pk:
            return

        for upload in self.cleaned_data.get('attachment_files', []):
            is_safe, reason = self.scan_attachment(upload)
            if not is_safe:
                raise ValidationError(reason or 'Attachment blocked by security scan.')

            PatchNoteAttachment.objects.create(
                patch_note=patch_note,
                file=upload,
                uploaded_by=uploaded_by,
            )


class PatchNoteCommentForm(forms.ModelForm):
    class Meta:
        model = PatchNoteComment
        fields = ['comment']
        widgets = {
            'comment': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 2,
                    'placeholder': 'Write a comment on this patch note',
                }
            ),
        }
