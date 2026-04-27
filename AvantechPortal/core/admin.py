from django.contrib import admin

from .models import (
	AssetAccountability,
	AssetDepartment,
	AssetItem,
	AssetItemImage,
	AssetItemType,
	AssetTagBatch,
	AssetTagEntry,
	Client,
	ClientDeletionRequest,
	ClientQuotation,
	ClientQuotationDocument,
	CompanyInternetAccount,
	DatabaseFile,
	DevelopmentFeedback,
	DevelopmentFeedbackComment,
	EmailVerificationToken,
	FundRequest,
	FundRequestAutoApproveRule,
	FundRequestLineItem,
	FundRequestTemplate,
	Liquidation,
	LiquidationAttachment,
	LiquidationLineItem,
	LiquidationTemplate,
	LoginEvent,
	Notification,
	SupportTicket,
	SupportTicketMessage,
	PatchNote,
	PatchNoteAttachment,
	PatchNoteComment,
	PatchNoteReaction,
	UserProfile,
)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
	list_display = ('user', 'email_verified', 'last_login_ip')
	search_fields = ('user__username', 'user__email')


@admin.register(LoginEvent)
class LoginEventAdmin(admin.ModelAdmin):
	list_display = ('username_attempt', 'successful', 'reason', 'ip_address', 'created_at')
	list_filter = ('successful', 'reason', 'created_at')
	search_fields = ('username_attempt', 'ip_address')


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
	list_display = ('user', 'token', 'created_at', 'expires_at', 'used_at')
	search_fields = ('user__username', 'user__email', 'token')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
	list_display = ('user', 'title', 'is_read', 'created_at', 'read_at')
	list_filter = ('is_read', 'created_at')
	search_fields = ('user__username', 'user__email', 'title', 'message')


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
	list_display = (
		'ticket_number',
		'title',
		'category',
		'status',
		'is_archived',
		'requested_priority',
		'support_priority',
		'created_by',
		'assigned_to',
		'created_at',
		'last_message_at',
		'archived_at',
		'archived_by',
	)
	list_filter = ('category', 'status', 'is_archived', 'requested_priority', 'support_priority', 'created_at', 'archived_at')
	search_fields = ('ticket_number', 'title', 'description', 'created_by__username', 'assigned_to__username')
	readonly_fields = (
		'ticket_number',
		'created_at',
		'updated_at',
		'assigned_at',
		'last_message_at',
		'last_activity_at',
		'closed_at',
		'archived_at',
	)


@admin.register(SupportTicketMessage)
class SupportTicketMessageAdmin(admin.ModelAdmin):
	list_display = ('ticket', 'sender', 'created_at')
	list_filter = ('created_at',)
	search_fields = ('ticket__ticket_number', 'message', 'sender__username', 'sender__email')


@admin.register(DevelopmentFeedback)
class DevelopmentFeedbackAdmin(admin.ModelAdmin):
	list_display = ('category', 'title', 'created_by', 'status', 'created_at')
	list_filter = ('category', 'status', 'created_at')
	search_fields = ('title', 'message', 'created_by__username', 'created_by__email')


@admin.register(DevelopmentFeedbackComment)
class DevelopmentFeedbackCommentAdmin(admin.ModelAdmin):
	list_display = ('feedback', 'created_by', 'created_at')
	list_filter = ('created_at',)
	search_fields = ('feedback__title', 'comment', 'created_by__username', 'created_by__email')


@admin.register(PatchNote)
class PatchNoteAdmin(admin.ModelAdmin):
	list_display = ('version', 'title', 'published_at', 'is_published', 'created_by')
	list_filter = ('is_published', 'published_at')
	search_fields = ('version', 'title', 'details', 'created_by__username')


@admin.register(PatchNoteComment)
class PatchNoteCommentAdmin(admin.ModelAdmin):
	list_display = ('patch_note', 'created_by', 'created_at')
	list_filter = ('created_at',)
	search_fields = ('patch_note__title', 'comment', 'created_by__username', 'created_by__email')


@admin.register(PatchNoteReaction)
class PatchNoteReactionAdmin(admin.ModelAdmin):
	list_display = ('patch_note', 'reaction', 'created_by', 'created_at')
	list_filter = ('reaction', 'created_at')
	search_fields = ('patch_note__title', 'created_by__username', 'created_by__email')


@admin.register(PatchNoteAttachment)
class PatchNoteAttachmentAdmin(admin.ModelAdmin):
	list_display = ('patch_note', 'uploaded_by', 'created_at')
	list_filter = ('created_at',)
	search_fields = ('patch_note__title', 'file', 'uploaded_by__username', 'uploaded_by__email')


@admin.register(DatabaseFile)
class DatabaseFileAdmin(admin.ModelAdmin):
	list_display = ('database_type', 'database_name', 'uploaded_by', 'created_at')
	list_filter = ('database_type', 'created_at')
	search_fields = ('database_name', 'notes', 'uploaded_by__username')


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):
	list_display = ('full_name', 'email', 'active_phone_number', 'client_type', 'status', 'lead_status', 'handled_by', 'handled_date')
	list_filter = ('client_type', 'status', 'lead_status', 'property_status', 'handled_date')
	search_fields = ('full_name', 'email', 'active_phone_number', 'exact_address', 'lead_disposition_reason')


@admin.register(ClientDeletionRequest)
class ClientDeletionRequestAdmin(admin.ModelAdmin):
	list_display = (
		'client_name_snapshot',
		'status',
		'requested_by',
		'requested_at',
		'resubmission_count',
		'reviewed_by',
		'reviewed_at',
	)
	list_filter = ('status', 'requested_at', 'reviewed_at')
	search_fields = ('client_name_snapshot', 'reason', 'review_notes', 'requested_by__username', 'reviewed_by__username')


@admin.register(ClientQuotation)
class ClientQuotationAdmin(admin.ModelAdmin):
	list_display = ('client', 'version', 'product_package', 'quoted_amount', 'negotiation_status', 'sent_by', 'sent_at', 'has_scanned_document')
	list_filter = ('negotiation_status', 'sent_at')
	search_fields = ('client__full_name', 'client__email', 'product_package', 'quotation_notes')

	def has_scanned_document(self, obj):
		return bool(obj.scanned_document)
	has_scanned_document.boolean = True
	has_scanned_document.short_description = 'Scanned Doc'


@admin.register(ClientQuotationDocument)
class ClientQuotationDocumentAdmin(admin.ModelAdmin):
	list_display = ('quotation', 'uploaded_by', 'uploaded_at')
	list_filter = ('uploaded_at',)
	search_fields = ('quotation__client__full_name', 'quotation__client__email', 'file')


@admin.register(FundRequestTemplate)
class FundRequestTemplateAdmin(admin.ModelAdmin):
	list_display = ('name', 'is_active', 'uploaded_by', 'updated_at')
	list_filter = ('is_active', 'updated_at')
	search_fields = ('name', 'notes', 'uploaded_by__username', 'uploaded_by__email')


@admin.register(FundRequest)
class FundRequestAdmin(admin.ModelAdmin):
	list_display = ('serial_number', 'requester_name', 'request_date', 'department', 'branch', 'total_amount', 'created_by')
	list_filter = ('request_year', 'request_date', 'department', 'branch')
	search_fields = ('serial_number', 'requester_name', 'department', 'branch')
	readonly_fields = ('serial_number', 'request_year', 'serial_sequence', 'total_amount', 'created_at', 'updated_at')


@admin.register(FundRequestLineItem)
class FundRequestLineItemAdmin(admin.ModelAdmin):
	list_display = ('fund_request', 'entry_date', 'particulars', 'amount')
	list_filter = ('entry_date',)
	search_fields = ('fund_request__serial_number', 'particulars')


@admin.register(FundRequestAutoApproveRule)
class FundRequestAutoApproveRuleAdmin(admin.ModelAdmin):
	list_display = ('name', 'is_active', 'created_by', 'updated_at')
	list_filter = ('is_active', 'updated_at')
	search_fields = ('name', 'requester_keyword', 'department_keyword', 'branch_keyword', 'reason')


@admin.register(LiquidationTemplate)
class LiquidationTemplateAdmin(admin.ModelAdmin):
	list_display = ('name', 'is_active', 'uploaded_by', 'updated_at')
	list_filter = ('is_active', 'updated_at')
	search_fields = ('name', 'notes', 'uploaded_by__username', 'uploaded_by__email')


@admin.register(Liquidation)
class LiquidationAdmin(admin.ModelAdmin):
	list_display = ('control_number', 'name', 'liquidation_date', 'branch', 'position', 'returned_or_over_type', 'total_amount', 'created_by')
	list_filter = ('liquidation_date', 'branch', 'position')
	search_fields = ('control_number', 'name', 'branch', 'position', 'requested_by_name')
	readonly_fields = ('control_number', 'request_year', 'control_sequence', 'total_amount', 'created_at', 'updated_at')


@admin.register(LiquidationLineItem)
class LiquidationLineItemAdmin(admin.ModelAdmin):
	list_display = ('liquidation', 'entry_date', 'fund_form_no', 'description', 'amount')
	list_filter = ('entry_date',)
	search_fields = ('liquidation__name', 'fund_form_no', 'description')


@admin.register(LiquidationAttachment)
class LiquidationAttachmentAdmin(admin.ModelAdmin):
	list_display = ('liquidation', 'uploaded_by', 'created_at')
	list_filter = ('created_at',)
	search_fields = ('liquidation__control_number', 'liquidation__name', 'image')


@admin.register(AssetDepartment)
class AssetDepartmentAdmin(admin.ModelAdmin):
	list_display = ('name', 'is_default', 'created_at')
	list_filter = ('is_default',)
	search_fields = ('name',)


@admin.register(AssetItem)
class AssetItemAdmin(admin.ModelAdmin):
	list_display = ('item_code', 'item_name', 'department', 'item_type', 'parent_item', 'stock_quantity', 'low_stock_threshold', 'is_active')
	list_filter = ('department', 'item_type', 'is_active')
	search_fields = ('item_code', 'item_name', 'specification', 'department__name')


@admin.register(AssetItemType)
class AssetItemTypeAdmin(admin.ModelAdmin):
	list_display = ('name', 'code', 'prefix', 'is_active', 'updated_at')
	list_filter = ('is_active',)
	search_fields = ('name', 'code', 'prefix')


@admin.register(AssetItemImage)
class AssetItemImageAdmin(admin.ModelAdmin):
	list_display = ('item', 'uploaded_at')
	list_filter = ('uploaded_at',)
	search_fields = ('item__item_code', 'item__item_name', 'image')


@admin.register(AssetTagBatch)
class AssetTagBatchAdmin(admin.ModelAdmin):
	list_display = ('id', 'department', 'generated_by', 'created_at')
	list_filter = ('department', 'created_at')
	search_fields = ('department__name', 'generated_by__username', 'generated_by__first_name', 'generated_by__last_name')


@admin.register(AssetTagEntry)
class AssetTagEntryAdmin(admin.ModelAdmin):
	list_display = ('tag_code', 'item_code_snapshot', 'item_name_snapshot', 'department_name_snapshot', 'batch', 'sequence')
	list_filter = ('department_name_snapshot', 'batch')
	search_fields = ('tag_code', 'item_code_snapshot', 'item_name_snapshot', 'specification_snapshot', 'department_name_snapshot')


@admin.register(AssetAccountability)
class AssetAccountabilityAdmin(admin.ModelAdmin):
	list_display = ('item', 'borrowed_by', 'quantity_borrowed', 'request_status', 'processed_by', 'processed_at', 'status', 'date_borrowed', 'date_returned')
	list_filter = ('request_status', 'status', 'date_borrowed', 'item__department')
	search_fields = ('item__item_code', 'item__item_name', 'borrowed_by__username', 'borrowed_by__first_name', 'borrowed_by__last_name')
	readonly_fields = ('created_at', 'updated_at', 'date_borrowed')


@admin.register(CompanyInternetAccount)
class CompanyInternetAccountAdmin(admin.ModelAdmin):
	list_display = ('platform_name', 'account_identifier', 'auth_provider', 'submitted_by', 'holder_name_override', 'created_at', 'last_unlocked_at')
	list_filter = ('auth_provider', 'created_at', 'last_unlocked_at')
	search_fields = ('platform_name', 'account_identifier', 'login_email', 'credential_username', 'holder_name_override', 'submitted_by__username')
	readonly_fields = ('created_at', 'updated_at', 'last_unlocked_at')
