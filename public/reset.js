// ✅ دالة لجلب CSRF token من meta tag
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

function getToken() {
    const url = new URL(window.location.href)
    return url.searchParams.get("token")
}

document.getElementById("resetBtn")?.addEventListener("click", async () => {
    const pass1 = document.getElementById("pass1").value
    const pass2 = document.getElementById("pass2").value
    const msg = document.getElementById("msg")
    const csrfToken = getCsrfToken()

    msg.innerHTML = ""
    msg.className = ""

    if (pass1.length < 8) {
        msg.innerHTML = "Password must be at least 8 characters"
        msg.className = "error"
        return
    }

    if (!/[A-Z]/.test(pass1)) {
        msg.innerHTML = "Password must contain at least one uppercase letter"
        msg.className = "error"
        return
    }

    if (!/[a-z]/.test(pass1)) {
        msg.innerHTML = "Password must contain at least one lowercase letter"
        msg.className = "error"
        return
    }

    if (!/[0-9]/.test(pass1)) {
        msg.innerHTML = "Password must contain at least one number"
        msg.className = "error"
        return
    }

    if (pass1 !== pass2) {
        msg.innerHTML = "Passwords do not match"
        msg.className = "error"
        return
    }

    const token = getToken()

    try {
        const res = await fetch("/api/reset-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({
                token,
                password: pass1
            })
        })

        const data = await res.json()

        if (res.ok) {
            msg.innerText = "Password reset successful"
            msg.className = "success"

            setTimeout(() => {
                window.location = "/admin/dashboard.html"
            }, 1500)
        } else {
            msg.innerText = data.error || "Reset failed"
            msg.className = "error"
        }
    } catch (e) {
        console.error("Reset password error:", e)
        msg.innerText = "Server error"
        msg.className = "error"
    }
})

// Also allow Enter key
document.getElementById("pass2")?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        document.getElementById("resetBtn")?.click()
    }
})