/**
 * SMS SENTINEL — Authentication Client Logic
 * Handles client-side validation, password toggles, theme management, API calls, and session state.
 */

function updateThemeIcons(theme) {
    const sun = document.getElementById("themeIconSun");
    const moon = document.getElementById("themeIconMoon");
    if (sun && moon) {
        if (theme === "light") {
            sun.classList.add("hidden");
            moon.classList.remove("hidden");
        } else {
            sun.classList.remove("hidden");
            moon.classList.add("hidden");
        }
    }
}

function setSentinelTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
        localStorage.setItem("sms_sentinel_theme", theme);
    } catch (e) {}
    updateThemeIcons(theme);
}

// Initialize theme on script load
(function() {
    let theme = "light";
    try {
        theme = localStorage.getItem("sms_sentinel_theme") || "light";
    } catch (e) {
        theme = "light";
    }
    document.documentElement.setAttribute("data-theme", theme);
})();

document.addEventListener("DOMContentLoaded", () => {
    // 1. Theme Toggle Button
    let currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    updateThemeIcons(currentTheme);

    const themeToggleBtn = document.getElementById("authThemeToggle");
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", () => {
            const active = document.documentElement.getAttribute("data-theme") || "light";
            const next = active === "light" ? "dark" : "light";
            setSentinelTheme(next);
        });
    }

    // 2. Password Visibility Toggle
    const toggleBtn = document.getElementById("togglePasswordBtn");
    const passwordInput = document.getElementById("password");
    const confirmInput = document.getElementById("confirmPassword");
    const eyeIcon = document.getElementById("eyeIcon");

    if (toggleBtn && passwordInput) {
        toggleBtn.addEventListener("click", () => {
            const isPassword = passwordInput.getAttribute("type") === "password";
            const newType = isPassword ? "text" : "password";
            passwordInput.setAttribute("type", newType);
            if (confirmInput) {
                confirmInput.setAttribute("type", newType);
            }

            if (isPassword) {
                // Show "eye-off" icon
                eyeIcon.innerHTML = `
                    <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/>
                    <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/>
                    <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/>
                    <line x1="2" y1="2" x2="22" y2="22"/>
                `;
            } else {
                // Show standard eye icon
                eyeIcon.innerHTML = `
                    <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
                    <circle cx="12" cy="3" r="3"/>
                `;
            }
        });
    }

    // 3. Alert helpers
    const alertBox = document.getElementById("authAlert");
    const alertText = document.getElementById("authAlertText");

    function showAlert(msg, isSuccess = false) {
        if (!alertBox || !alertText) return;
        alertText.textContent = msg;
        alertBox.className = isSuccess ? "auth-alert success" : "auth-alert";
        alertBox.classList.remove("hidden");
    }

    function hideAlert() {
        if (!alertBox) return;
        alertBox.classList.add("hidden");
    }

    // 4. Button state helper
    const submitBtn = document.getElementById("submitBtn");
    const btnText = document.getElementById("btnText");
    const btnSpinner = document.getElementById("btnSpinner");

    function setSubmitting(isSubmitting, loadingText = "Submitting...") {
        if (!submitBtn) return;
        submitBtn.disabled = isSubmitting;
        if (isSubmitting) {
            if (btnText) btnText.textContent = loadingText;
            if (btnSpinner) btnSpinner.classList.remove("hidden");
        } else {
            if (btnSpinner) btnSpinner.classList.add("hidden");
        }
    }

    // 5. Handle Login Form Submission
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideAlert();

            const email = (document.getElementById("email")?.value || "").trim();
            const password = document.getElementById("password")?.value || "";

            // Client Validation
            if (!email) {
                showAlert("Please enter your email address.");
                document.getElementById("email")?.focus();
                return;
            }
            if (!email.includes("@") || !email.includes(".")) {
                showAlert("Please enter a valid email address.");
                document.getElementById("email")?.focus();
                return;
            }
            if (!password) {
                showAlert("Please enter your password.");
                document.getElementById("password")?.focus();
                return;
            }

            setSubmitting(true, "Signing in...");

            try {
                const response = await fetch("/api/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showAlert("Authentication successful! Launching dashboard...", true);
                    setTimeout(() => {
                        window.location.href = "/";
                    }, 400);
                } else {
                    showAlert(result.error || "Invalid email or password.");
                    setSubmitting(false);
                    if (btnText) btnText.innerHTML = "Sign in &rarr;";
                }
            } catch (err) {
                console.error("Login fetch error:", err);
                showAlert("Unable to connect to server. Please try again.");
                setSubmitting(false);
                if (btnText) btnText.innerHTML = "Sign in &rarr;";
            }
        });
    }

    // 6. Handle Register Form Submission
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            hideAlert();

            const name = (document.getElementById("name")?.value || "").trim();
            const email = (document.getElementById("email")?.value || "").trim();
            const password = document.getElementById("password")?.value || "";
            const confirmPassword = document.getElementById("confirmPassword")?.value || "";

            // Client Validation
            if (!name) {
                showAlert("Please enter your full name.");
                document.getElementById("name")?.focus();
                return;
            }
            if (!email || !email.includes("@") || !email.includes(".")) {
                showAlert("Please enter a valid email address.");
                document.getElementById("email")?.focus();
                return;
            }
            if (password.length < 8) {
                showAlert("Password must be at least 8 characters long.");
                document.getElementById("password")?.focus();
                return;
            }
            if (password !== confirmPassword) {
                showAlert("Passwords do not match. Please re-enter.");
                document.getElementById("confirmPassword")?.focus();
                return;
            }

            setSubmitting(true, "Creating account...");

            try {
                const response = await fetch("/api/auth/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        name,
                        email,
                        password,
                        confirm_password: confirmPassword
                    })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showAlert("Account created successfully! Launching dashboard...", true);
                    setTimeout(() => {
                        window.location.href = "/";
                    }, 500);
                } else {
                    showAlert(result.error || "Registration failed. Please try again.");
                    setSubmitting(false);
                    if (btnText) btnText.innerHTML = "Create account &rarr;";
                }
            } catch (err) {
                console.error("Registration fetch error:", err);
                showAlert("Unable to connect to server. Please try again.");
                setSubmitting(false);
                if (btnText) btnText.innerHTML = "Create account &rarr;";
            }
        });
    }

    // 7. Check for OAuth error/status in URL query params on page load
    (function checkUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get("error");
        const msg = urlParams.get("msg");
        const provider = urlParams.get("provider");

        if (msg) {
            showAlert(msg);
        } else if (error) {
            const errorMap = {
                "cancelled": "Sign-in was cancelled.",
                "access_denied": "Access was denied by the identity provider.",
                "config_missing": `${provider ? provider.toUpperCase() : "Social"} sign-in is not configured yet.`,
                "invalid_state": "Session security state expired. Please try again.",
                "token_exchange_failed": "Unable to complete social sign-in. Please try again.",
                "identity_error": "Could not retrieve verified profile from provider.",
                "unsupported_provider": "Unsupported login provider."
            };
            showAlert(errorMap[error] || "Unable to complete social authentication.");
        }
    })();

    // 8. Interactive Forgot Password Link
    const forgotLink = document.getElementById("forgotPassLink");
    if (forgotLink) {
        forgotLink.addEventListener("click", (e) => {
            e.preventDefault();
            showAlert("To reset your password, please contact your system administrator.");
        });
    }
});
