from collections import defaultdict


FEATURE_LABELS = {
    ('auth', 'user'): ('user_accounts', 'User Accounts'),
    ('auth', 'group'): ('roles_permissions', 'Roles & Permissions'),
    ('auth', 'permission'): ('roles_permissions', 'Roles & Permissions'),
    ('axes', 'accessattempt'): ('login_security', 'Login Security & Lockouts'),
    ('axes', 'accessattemptexpiration'): ('login_security', 'Login Security & Lockouts'),
    ('axes', 'accessfailurelog'): ('login_security', 'Login Security & Lockouts'),
    ('axes', 'accesslog'): ('login_security', 'Login Security & Lockouts'),
    ('core', 'assetaccountability'): ('asset_accountability', 'Asset Accountability'),
    ('core', 'assetreturnproof'): ('asset_accountability', 'Asset Accountability'),
    ('core', 'assetdepartment'): ('asset_inventory', 'Asset Inventory'),
    ('core', 'assetitem'): ('asset_inventory', 'Asset Inventory'),
    ('core', 'assetitemimage'): ('asset_inventory', 'Asset Inventory'),
    ('core', 'assetitemtype'): ('asset_inventory', 'Asset Inventory'),
    ('core', 'assettagbatch'): ('asset_tags', 'Asset Tags & Documents'),
    ('core', 'assettagentry'): ('asset_tags', 'Asset Tags & Documents'),
    ('core', 'companyinternetaccount'): ('internet_accounts', 'Internet Accounts'),
    ('core', 'client'): ('clients', 'Client Management'),
    ('core', 'clientdeletionrequest'): ('clients', 'Client Management'),
    ('core', 'clientquotation'): ('clients', 'Client Management'),
    ('core', 'clientquotationdocument'): ('clients', 'Client Management'),
    ('core', 'fundrequest'): ('fund_requests', 'Fund Requests'),
    ('core', 'fundrequestattachment'): ('fund_requests', 'Fund Requests'),
    ('core', 'fundrequestautoapproverule'): ('fund_requests', 'Fund Requests'),
    ('core', 'fundrequestlineitem'): ('fund_requests', 'Fund Requests'),
    ('core', 'fundrequesttemplate'): ('fund_requests', 'Fund Requests'),
    ('core', 'liquidation'): ('liquidations', 'Liquidations'),
    ('core', 'liquidationattachment'): ('liquidations', 'Liquidations'),
    ('core', 'liquidationlineitem'): ('liquidations', 'Liquidations'),
    ('core', 'liquidationsettings'): ('liquidations', 'Liquidations'),
    ('core', 'liquidationtemplate'): ('liquidations', 'Liquidations'),
    ('core', 'databasefile'): ('system_backups', 'System Backups'),
    ('core', 'systembackup'): ('system_backups', 'System Backups'),
    ('core', 'systembackupschedule'): ('system_backups', 'System Backups'),
    ('core', 'notification'): ('notifications', 'Notifications'),
    ('core', 'supportticket'): ('ticketing_support', 'Ticketing & IT Support'),
    ('core', 'supportticketmessage'): ('ticketing_support', 'Ticketing & IT Support'),
    ('core', 'developmentfeedback'): ('development_feedback', 'Development Feedback'),
    ('core', 'developmentfeedbackcomment'): ('development_feedback', 'Development Feedback'),
    ('core', 'patchnote'): ('patch_notes', 'Patch Notes'),
    ('core', 'patchnoteattachment'): ('patch_notes', 'Patch Notes'),
    ('core', 'patchnotecomment'): ('patch_notes', 'Patch Notes'),
    ('core', 'patchnotereaction'): ('patch_notes', 'Patch Notes'),
    ('core', 'emailverificationtoken'): ('account_security', 'Account Security'),
    ('core', 'loginevent'): ('account_security', 'Account Security'),
    ('core', 'userprofile'): ('account_security', 'Account Security'),
}

FEATURE_ORDER = [
    'user_accounts',
    'roles_permissions',
    'login_security',
    'clients',
    'fund_requests',
    'liquidations',
    'asset_inventory',
    'asset_tags',
    'asset_accountability',
    'internet_accounts',
    'notifications',
    'ticketing_support',
    'system_backups',
    'development_feedback',
    'patch_notes',
    'account_security',
    'system_internals',
]

RESOURCE_LABELS = {
    ('auth', 'user'): 'user accounts',
    ('auth', 'group'): 'roles',
    ('auth', 'permission'): 'permission definitions',
    ('axes', 'accessattempt'): 'lockout attempts',
    ('axes', 'accessattemptexpiration'): 'lockout expiration records',
    ('axes', 'accessfailurelog'): 'failed login records',
    ('axes', 'accesslog'): 'access logs',
    ('core', 'assetaccountability'): 'asset accountability records',
    ('core', 'assetdepartment'): 'asset departments',
    ('core', 'assetitem'): 'asset items',
    ('core', 'assetitemimage'): 'asset item images',
    ('core', 'assetitemtype'): 'asset item types',
    ('core', 'assetreturnproof'): 'asset return proofs',
    ('core', 'assettagbatch'): 'asset tag batches',
    ('core', 'assettagentry'): 'asset tag entries',
    ('core', 'client'): 'clients',
    ('core', 'clientdeletionrequest'): 'client deletion requests',
    ('core', 'clientquotation'): 'client quotations',
    ('core', 'clientquotationdocument'): 'client quotation documents',
    ('core', 'companyinternetaccount'): 'company internet accounts',
    ('core', 'databasefile'): 'database files',
    ('core', 'developmentfeedback'): 'development feedback records',
    ('core', 'developmentfeedbackcomment'): 'development feedback comments',
    ('core', 'emailverificationtoken'): 'email verification tokens',
    ('core', 'fundrequest'): 'fund requests',
    ('core', 'fundrequestattachment'): 'fund request attachments',
    ('core', 'fundrequestautoapproverule'): 'fund request auto-approve rules',
    ('core', 'fundrequestlineitem'): 'fund request line items',
    ('core', 'fundrequesttemplate'): 'fund request templates',
    ('core', 'liquidation'): 'liquidation records',
    ('core', 'liquidationattachment'): 'liquidation attachments',
    ('core', 'liquidationlineitem'): 'liquidation line items',
    ('core', 'liquidationsettings'): 'liquidation settings',
    ('core', 'liquidationtemplate'): 'liquidation templates',
    ('core', 'loginevent'): 'login events',
    ('core', 'notification'): 'notifications',
    ('core', 'supportticket'): 'support tickets',
    ('core', 'supportticketmessage'): 'support ticket messages',
    ('core', 'patchnote'): 'patch notes',
    ('core', 'patchnoteattachment'): 'patch note attachments',
    ('core', 'patchnotecomment'): 'patch note comments',
    ('core', 'patchnotereaction'): 'patch note reactions',
    ('core', 'systembackup'): 'system backups',
    ('core', 'systembackupschedule'): 'system backup schedules',
    ('core', 'userprofile'): 'user profiles',
}

CUSTOM_PERMISSION_LABELS = {
    ('core', 'assetaccountability', 'can_borrow_assets'): 'Submit asset borrow requests',
    ('core', 'assetaccountability', 'can_manage_accountability'): 'Review and manage asset accountability requests',
    ('core', 'assetitemtype', 'view_assettrackercategory'): 'Open asset tracker category view',
    ('core', 'clientdeletionrequest', 'approve_clientdeletionrequest'): 'Approve client deletion requests',
    ('core', 'companyinternetaccount', 'reveal_companyinternetaccount_password'): 'Unlock and view internet account passwords',
    ('core', 'supportticket', 'can_manage_supportticket'): 'Manage all support tickets',
}

ACTION_LABELS = {
    'add': 'Create',
    'change': 'Edit',
    'delete': 'Delete',
    'view': 'View',
}

INTERNAL_APP_LABELS = {
    'admin',
    'captcha',
    'contenttypes',
    'otp_static',
    'otp_totp',
    'sessions',
}


def _split_codename(codename):
    for action in ('view', 'add', 'change', 'delete'):
        prefix = f'{action}_'
        if codename.startswith(prefix):
            return action, codename[len(prefix):]
    return '', codename


def _normalize_words(value):
    return str(value or '').replace('_', ' ').strip().lower()


def _feature_for_permission(permission):
    model_key = (permission.content_type.app_label, permission.content_type.model)
    if model_key in FEATURE_LABELS:
        return FEATURE_LABELS[model_key]

    if permission.content_type.app_label in INTERNAL_APP_LABELS:
        return 'system_internals', 'System Internals (Advanced)'

    if permission.content_type.app_label == 'core':
        return 'system_internals', 'System Internals (Advanced)'
    return 'system_internals', 'System Internals (Advanced)'


def _resource_label_for_permission(permission):
    model_key = (permission.content_type.app_label, permission.content_type.model)
    if model_key in RESOURCE_LABELS:
        return RESOURCE_LABELS[model_key]
    return _normalize_words(permission.content_type.model) or 'records'


def describe_permission(permission):
    model_key = (permission.content_type.app_label, permission.content_type.model)
    feature_key, feature_label = _feature_for_permission(permission)
    custom_label = CUSTOM_PERMISSION_LABELS.get((model_key[0], model_key[1], permission.codename))
    if custom_label:
        return {
            'feature_key': feature_key,
            'feature_label': feature_label,
            'permission_label': custom_label,
        }

    action_key, _ = _split_codename(permission.codename)
    resource_label = _resource_label_for_permission(permission)
    if action_key in ACTION_LABELS:
        permission_label = f'{ACTION_LABELS[action_key]} {resource_label}'
    else:
        fallback_label = str(permission.name or '').strip()
        if fallback_label.lower().startswith('can '):
            fallback_label = fallback_label[4:]
        permission_label = fallback_label[:1].upper() + fallback_label[1:] if fallback_label else 'Use this capability'

    return {
        'feature_key': feature_key,
        'feature_label': feature_label,
        'permission_label': permission_label,
    }


def format_permission_summary(permission):
    meta = describe_permission(permission)
    return f"{meta['feature_label']}: {meta['permission_label']}"


def build_permission_groups(permissions, selected_values=None):
    selected_lookup = {str(value) for value in (selected_values or set())}
    grouped = defaultdict(list)
    labels_by_key = {}

    for permission in permissions:
        meta = describe_permission(permission)
        feature_key = meta['feature_key']
        labels_by_key[feature_key] = meta['feature_label']
        grouped[feature_key].append(
            {
                'value': str(permission.pk),
                'label': meta['permission_label'],
                'checked': str(permission.pk) in selected_lookup,
            }
        )

    order_lookup = {key: index for index, key in enumerate(FEATURE_ORDER)}
    ordered_keys = sorted(
        grouped.keys(),
        key=lambda key: (order_lookup.get(key, len(FEATURE_ORDER) + 1), labels_by_key.get(key, key)),
    )

    result = []
    for feature_key in ordered_keys:
        items = sorted(grouped[feature_key], key=lambda item: item['label'])
        selected_count = sum(1 for item in items if item['checked'])
        result.append(
            {
                'feature_key': feature_key,
                'feature_label': labels_by_key.get(feature_key, feature_key.replace('_', ' ').title()),
                'app_label': labels_by_key.get(feature_key, feature_key.replace('_', ' ').title()),
                'items': items,
                'selected_count': selected_count,
                'total_count': len(items),
            }
        )

    return result


def build_permission_preview_groups(permissions):
    grouped = build_permission_groups(permissions)
    return [
        {
            'app_label': group['app_label'],
            'items': [item['label'] for item in group['items']],
        }
        for group in grouped
    ]
