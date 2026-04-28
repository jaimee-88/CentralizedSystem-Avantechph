(function () {
    function markFieldState(field) {
        if (!field || !field.closest) {
            return;
        }
        var container = field.closest('.mb-2, .mb-3, .mb-4, .mb-5, .form-group, .row, .col, .col-md-6, .col-lg-6') || field.parentElement;
        if (!container || !container.classList) {
            return;
        }
        if (typeof field.checkValidity === 'function' && !field.checkValidity()) {
            container.classList.add('field-has-error');
        } else {
            container.classList.remove('field-has-error');
        }
    }

    function wireFormValidation(form) {
        if (!form || form.dataset.validationBound === '1') {
            return;
        }
        form.dataset.validationBound = '1';
        form.removeAttribute('novalidate');

        form.addEventListener('submit', function (event) {
            var submitter = event.submitter;
            if (submitter && (submitter.hasAttribute('formnovalidate') || submitter.dataset.skipValidation === '1')) {
                return;
            }

            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
                form.classList.add('was-validated');
                form.querySelectorAll('input, select, textarea').forEach(markFieldState);
            }
        });

        form.querySelectorAll('input, select, textarea').forEach(function (field) {
            field.addEventListener('input', function () {
                markFieldState(field);
            });
            field.addEventListener('change', function () {
                markFieldState(field);
            });
        });
    }

    function wirePasswordToggle(input) {
        if (!input || input.dataset.passwordToggleBound === '1') {
            return;
        }
        input.dataset.passwordToggleBound = '1';

        var currentType = (input.getAttribute('type') || '').toLowerCase();
        if (currentType !== 'password') {
            return;
        }

        if (input.parentElement && input.parentElement.classList.contains('password-toggle-wrap')) {
            return;
        }

        var wrapper = document.createElement('div');
        wrapper.className = 'input-group password-toggle-wrap';
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        var button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-outline-secondary password-toggle-btn';
        button.setAttribute('aria-label', 'Show password');
        button.setAttribute('aria-pressed', 'false');
        button.innerHTML = '<span class="password-toggle-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M12 15.5A3.5 3.5 0 1 0 12 8.5A3.5 3.5 0 1 0 12 15.5Z" stroke="currentColor" stroke-width="1.8"/><path class="password-toggle-slash" d="M4 20L20 4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></span>';

        button.addEventListener('click', function () {
            var isPassword = input.getAttribute('type') === 'password';
            input.setAttribute('type', isPassword ? 'text' : 'password');
            button.classList.toggle('is-visible', isPassword);
            button.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
            button.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
        });

        wrapper.appendChild(button);
    }

    function refreshCaptcha(button) {
        var refreshUrl = button.dataset.captchaRefreshUrl;
        if (!refreshUrl || !window.fetch) {
            return;
        }

        var scope = button.closest('[data-captcha-scope="1"]') || button.closest('form') || document;
        var image = scope.querySelector('img.captcha') || scope.querySelector('img[alt="captcha"]');
        var hiddenKey = scope.querySelector('input[type="hidden"][name$="captcha_0"], input[type="hidden"][id$="captcha_0"]');
        var responseField = scope.querySelector('input[name$="captcha_1"], input[id$="captcha_1"]');

        button.disabled = true;

        fetch(refreshUrl, {
            credentials: 'same-origin',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            },
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('Failed to refresh captcha');
                }
                return response.json();
            })
            .then(function (data) {
                if (image && data && data.image_url) {
                    var separator = data.image_url.indexOf('?') === -1 ? '?' : '&';
                    image.setAttribute('src', data.image_url + separator + 'refresh=' + Date.now());
                }
                if (hiddenKey && data && data.key) {
                    hiddenKey.value = data.key;
                }
                if (responseField) {
                    responseField.value = '';
                    responseField.focus();
                }
            })
            .catch(function (error) {
                if (window.console && typeof window.console.warn === 'function') {
                    window.console.warn('Captcha refresh failed', error);
                }
            })
            .then(function () {
                button.disabled = false;
            });
    }

    function wireCaptchaRefresh(button) {
        if (!button) {
            return;
        }
        button.dataset.captchaRefreshBound = '1';
    }

    function enhance(root) {
        var scope = root || document;
        scope.querySelectorAll('form').forEach(wireFormValidation);
        scope.querySelectorAll('input[type="password"]').forEach(wirePasswordToggle);
        scope.querySelectorAll('.js-captcha-refresh').forEach(wireCaptchaRefresh);
    }

    document.addEventListener('DOMContentLoaded', function () {
        enhance(document);

        document.addEventListener('click', function (event) {
            var button = event.target.closest ? event.target.closest('.js-captcha-refresh') : null;
            if (!button) {
                return;
            }
            event.preventDefault();
            refreshCaptcha(button);
        });

        var observer = new MutationObserver(function (mutations) {
            mutations.forEach(function (mutation) {
                mutation.addedNodes.forEach(function (node) {
                    if (!(node instanceof Element)) {
                        return;
                    }
                    if (node.matches && (node.matches('form') || node.matches('input[type="password"]'))) {
                        enhance(node.parentElement || document);
                    } else if (node.querySelectorAll) {
                        enhance(node);
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });
    });

    window.AvantechFormEnhancer = {
        enhance: enhance,
    };
})();
