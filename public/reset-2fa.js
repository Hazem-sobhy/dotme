// ✅ دالة لجلب CSRF token من meta tag
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

const params = new URLSearchParams(window.location.search)
const token = params.get("token")

async function load() {
    const csrfToken = getCsrfToken()
    const errorEl = document.getElementById("error")
    const qrEl = document.getElementById("qr")

    // ✅ التحقق من وجود التوكن وصلاحيته
    if (!token || token.length < 20) {
        errorEl.innerText = "Invalid or expired link"
        return
    }

    try {
        const res = await fetch("/api/new-2fa", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ token })
        })

        const data = await res.json()

        if (data.qr) {
            qrEl.src = data.qr
        } else {
            errorEl.innerText = data.error || "Invalid or expired link"
        }
    } catch (e) {
        console.error("Reset 2FA error:", e)
        errorEl.innerText = "Server error. Please try again later."
    }
}

load()