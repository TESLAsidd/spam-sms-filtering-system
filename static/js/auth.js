/**
 * SMS SENTINEL — Authentication Client Logic
 * Handles client-side validation, password toggles, API calls, and session state.
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Password Visibility Toggle
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
                    <circle cx="12" cy="12" r="3"/>
                `;
            }
        });
    }

    // 2. Alert helpers
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

    // 3. Button state helper
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

    // 4. Handle Login Form Submission
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
                    showAlert("Authentication successful! Redirecting...", true);
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

    // 5. Handle Register Form Submission
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
});
