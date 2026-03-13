// ✅ دالة لجلب CSRF token من meta tag أو من cookie (كبديل)
function getCsrfToken() {
    // حاول تجيب التوكن من meta tag
    const metaToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
    if (metaToken) return metaToken
    
    // لو مش موجود، جرب تجيبه من cookie (كبديل)
    const cookies = document.cookie.split(';')
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=')
        if (name === 'csrf-token') return value
    }
    
    // لو لسه مش موجود، استخدم empty string
    console.warn("CSRF token not found")
    return ''
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

        if (!res.ok) {
            throw new Error(data.error || "Failed to reset 2FA")
        }

        if (data.qr) {
            qrEl.src = data.qr
            qrEl.style.display = 'block'
            errorEl.innerText = ''
        } else {
            errorEl.innerText = data.error || "Invalid or expired link"
        }
    } catch (e) {
        console.error("Reset 2FA error:", e)
        errorEl.innerText = e.message || "Server error. Please try again later."
    }
}

// شغل load لما الصفحة تتحمل
document.addEventListener('DOMContentLoaded', load)