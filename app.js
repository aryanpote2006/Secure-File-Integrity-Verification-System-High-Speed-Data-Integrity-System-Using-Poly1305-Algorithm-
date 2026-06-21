const dropZone = document.getElementById("dropZone");
const fileInput = document.getElementById("fileInput");
const progressBar = document.getElementById("progressBar");

if (dropZone && fileInput) {
    ["dragenter", "dragover"].forEach((eventName) => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropZone.classList.add("drag");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropZone.classList.remove("drag");
        });
    });

    dropZone.addEventListener("drop", (event) => {
        const files = event.dataTransfer.files;
        if (files.length) {
            fileInput.files = files;
            dropZone.querySelector("strong").textContent = files[0].name;
            if (progressBar) progressBar.style.width = "100%";
        }
    });

    fileInput.addEventListener("change", () => {
        if (fileInput.files.length) {
            dropZone.querySelector("strong").textContent = fileInput.files[0].name;
            if (progressBar) progressBar.style.width = "100%";
        }
    });
}

const chart = document.getElementById("statsChart");
if (chart) {
    const ctx = chart.getContext("2d");
    const values = [
        Number(chart.dataset.registered || 0),
        Number(chart.dataset.verified || 0),
        Number(chart.dataset.tampered || 0),
    ];
    const labels = ["Registered", "Verified", "Tampered"];
    const colors = ["#35d0ba", "#47d16c", "#ff5f68"];
    const max = Math.max(...values, 1);
    ctx.clearRect(0, 0, chart.width, chart.height);
    ctx.font = "14px Segoe UI";
    values.forEach((value, index) => {
        const y = 46 + index * 70;
        const width = (value / max) * 330;
        ctx.fillStyle = "#8da1b3";
        ctx.fillText(labels[index], 20, y);
        ctx.fillStyle = "#09141e";
        ctx.fillRect(130, y - 18, 340, 28);
        ctx.fillStyle = colors[index];
        ctx.fillRect(130, y - 18, width, 28);
        ctx.fillStyle = "#e7f0f7";
        ctx.fillText(String(value), 485, y);
    });
}

const resendButton = document.getElementById("resendButton");
if (resendButton) {
    let remaining = Number(resendButton.dataset.cooldown || 60);
    const original = "Resend Reset Link";
    const tick = () => {
        if (remaining > 0) {
            resendButton.disabled = true;
            resendButton.textContent = `${original} (${remaining}s)`;
            remaining -= 1;
            window.setTimeout(tick, 1000);
        } else {
            resendButton.disabled = false;
            resendButton.textContent = original;
        }
    };
    tick();
}

document.querySelectorAll(".toggle-password").forEach((button) => {
    button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.target);
        const visible = input.type === "text";
        input.type = visible ? "password" : "text";
        button.textContent = visible ? "Show" : "Hide";
    });
});

const passwordInput = document.getElementById("newPassword");
const confirmInput = document.getElementById("confirmPassword");
const strengthBar = document.getElementById("strengthBar");
const strengthLabel = document.getElementById("strengthLabel");
const checklist = document.getElementById("passwordChecklist");

function updatePasswordStrength() {
    if (!passwordInput || !strengthBar || !strengthLabel || !checklist) return;
    const password = passwordInput.value;
    const confirm = confirmInput ? confirmInput.value : "";
    const rules = {
        length: password.length >= 8,
        upper: /[A-Z]/.test(password),
        lower: /[a-z]/.test(password),
        number: /\d/.test(password),
        special: /[^A-Za-z0-9]/.test(password),
        match: password.length > 0 && password === confirm,
    };
    Object.entries(rules).forEach(([rule, valid]) => {
        const item = checklist.querySelector(`[data-rule="${rule}"]`);
        if (item) item.classList.toggle("valid", valid);
    });
    const score = ["length", "upper", "lower", "number", "special"].filter((rule) => rules[rule]).length;
    strengthBar.className = "";
    if (score >= 5) {
        strengthBar.classList.add("strong");
        strengthLabel.textContent = "Strong";
    } else if (score >= 3) {
        strengthBar.classList.add("medium");
        strengthLabel.textContent = "Medium";
    } else {
        strengthLabel.textContent = "Weak";
    }
}

if (passwordInput) passwordInput.addEventListener("input", updatePasswordStrength);
if (confirmInput) confirmInput.addEventListener("input", updatePasswordStrength);
updatePasswordStrength();

const resetPasswordForm = document.getElementById("resetPasswordForm");
if (resetPasswordForm && resetPasswordForm.dataset.success === "true") {
    window.setTimeout(() => {
        window.location.href = "/login";
    }, 2200);
}
